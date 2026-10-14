use super::*;

pub use crate::daemon::proto::InferenceErrorClass;

/// Sentinel error returned by [`Model::complete_captured`] when the
/// in-flight inference was aborted by a user ctrl+c (a `CancelTurn`
/// request). Distinct from a provider/transport failure so the driver
/// can unwind the turn cleanly (back to idle) rather than logging it as
/// a real error. Downcast through the `anyhow` chain to detect it.
#[derive(Debug, thiserror::Error)]
#[error("inference cancelled by user")]
pub struct InferenceCancelled {
    pub phase: InferencePhase,
}

/// Returns `true` when `err`'s chain carries an [`InferenceCancelled`]
/// sentinel — i.e. the turn was aborted by the user, not a real failure.
pub fn is_cancelled(err: &anyhow::Error) -> bool {
    err.downcast_ref::<InferenceCancelled>().is_some()
}

/// Sentinel returned only when an AgentTree late-user steer lost the final
/// runnable-owner race before any provider bytes were sent. This is neither a
/// user cancellation nor an inference failure: its durable row is still
/// pending and must remain ordered behind the owner continuation that parked
/// first.
#[derive(Debug, thiserror::Error)]
#[error("late user steer deferred until its owner is runnable")]
pub struct LateUserSteerDeferred;

pub fn is_late_user_steer_deferred(err: &anyhow::Error) -> bool {
    err.downcast_ref::<LateUserSteerDeferred>().is_some()
}

pub fn cancellation_phase(err: &anyhow::Error) -> Option<InferencePhase> {
    err.downcast_ref::<InferenceCancelled>()
        .map(|cancelled| cancelled.phase)
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

/// A well-typed, terminal inference failure — the clean hard-fail seam a
/// future per-model-backup-fallback
/// (implementation note) intercepts *before* the
/// failure reaches the user. A TTFT / idle timeout produces one directly
/// (it never loops through the transient-retry path); a non-retryable
/// transport / HTTP failure is mapped into one after the retry layer gives
/// up. Carries everything the inline error + the failure event need:
/// provider/model, the phase reached, the error class, and elapsed-ms since
/// dispatch.
/// A typed provider-recovery signal parsed from a terminal failure's error
/// body at the model boundary (issue #23). Core-internal (never a proto class):
/// it drives the billing/overload retry + failover POLICY without stuffing the
/// observed HTTP status into the semantic [`InferenceErrorClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub enum ProviderRecoverySignal {
    /// No specialized provider-recovery signal in the error body — every
    /// ordinary failure (timeouts, transport, generic HTTP status).
    #[default]
    None,
    /// Billing / account-quota exhaustion (structured code `1113` or one of the
    /// closed named phrases). Fail fast, then a different-provider backup only.
    BillingExhausted,
    /// Explicit provider overload (`server_is_overloaded` /
    /// `service_unavailable_error`). Exactly one same-model retry, then a
    /// cross-provider-preferred backup.
    Overloaded,
}

impl ProviderRecoverySignal {
    /// Monotonic significance rank used to accumulate the STRONGEST signal seen
    /// across a retry chain (billing outranks overload outranks none), so a
    /// later generic error cannot mask an earlier billing/overload signal.
    pub(crate) fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Overloaded => 1,
            Self::BillingExhausted => 2,
        }
    }

    /// Inverse of [`Self::rank`].
    pub(crate) fn from_rank(rank: u8) -> Self {
        match rank {
            0 => Self::None,
            1 => Self::Overloaded,
            _ => Self::BillingExhausted,
        }
    }

    /// Stable string form for the content-safe failure metadata carried on
    /// events/reports/audit records (the typed recovery signal is queryable
    /// even though the raw provider detail is omitted).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Overloaded => "overloaded",
            Self::BillingExhausted => "billing_exhausted",
        }
    }
}

/// The fixed omission marker emitted in place of any raw provider failure
/// detail. This constant is the SINGLE source of the marker string; no sink may
/// substitute its own spelling. Security invariant (GOALS §14, wire-vs-user
/// split): the raw provider text carried in [`InferenceFailure::detail`] must
/// never cross any channel — turn event, subagent report, failure envelope,
/// tracing log, or audit record. Every such sink projects the failure through
/// [`safe_provider_detail`], which returns this marker instead of the body.
pub const PROVIDER_DETAIL_OMITTED: &str = "provider_detail_omitted";

/// Content-safe projection of a terminal [`InferenceFailure`]'s free-text
/// detail. Carries the fixed [`PROVIDER_DETAIL_OMITTED`] marker in place of the
/// raw provider body, plus the TYPED classification metadata that stays
/// queryable across every sink: the observed HTTP status (issue #23) and the
/// typed provider-recovery signal. Constructed ONLY by [`safe_provider_detail`]
/// — the raw detail string is never read into it, so no holder can leak it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SafeProviderDetail {
    /// Always [`PROVIDER_DETAIL_OMITTED`]; never raw provider text.
    pub marker: &'static str,
    /// Observed HTTP status retained for diagnostics — the status the provider
    /// returned, not the semantic error class. `None` for pure timeout /
    /// transport / pre-dispatch failures.
    pub observed_status: Option<u16>,
    /// Typed provider-recovery signal parsed from the (now-omitted) error body.
    pub recovery: ProviderRecoverySignal,
}

impl SafeProviderDetail {
    /// The omission marker as an owned `String`, for the `detail: String`
    /// free-text sinks (turn events, failure envelopes, rendered reports).
    pub fn marker_string(&self) -> String {
        self.marker.to_string()
    }
}

/// THE single funnel every failure-detail sink routes through. Drops the raw
/// `failure.detail` provider text — it is never read into the return value —
/// and returns the fixed omission marker plus the typed classification metadata
/// (observed status class + recovery kind). Because the raw text never leaves
/// this function, no caller can leak it onto any channel.
pub fn safe_provider_detail(failure: &InferenceFailure) -> SafeProviderDetail {
    SafeProviderDetail {
        marker: PROVIDER_DETAIL_OMITTED,
        observed_status: failure
            .observed_status
            .or_else(|| failure.class.provider_status()),
        recovery: failure.recovery,
    }
}

/// The same omission funnel for a terminal failure path that holds a raw
/// [`rig::completion::CompletionError`] rather than an already-built
/// [`InferenceFailure`] — e.g. the single-shot tandem / second-opinion path.
/// Classifies the error through the SINGLE model-boundary classifier
/// ([`super::rig_boundary::classify_terminal_failure`]) to recover the typed
/// `(class, observed_status, recovery)`, then returns the fixed omission marker
/// plus that metadata. The raw error text (`err.to_string()`, an
/// attacker-controllable provider body) is NEVER read into the result, so no
/// caller can persist or emit it.
pub fn safe_completion_error_detail(err: &rig::completion::CompletionError) -> SafeProviderDetail {
    let classified = super::rig_boundary::classify_terminal_failure(err);
    SafeProviderDetail {
        marker: PROVIDER_DETAIL_OMITTED,
        observed_status: classified
            .observed_status
            .or_else(|| classified.class.provider_status()),
        recovery: classified.recovery,
    }
}

/// Content-safe projection for an inference error held behind `anyhow`.
///
/// Utility-model paths add context to Rig errors before deciding whether to
/// log or degrade. Rig 0.42's provider-response display includes the provider
/// request id, so those paths must not fall back to formatting the error when
/// the chain still contains a provider completion error. An already-typed
/// [`InferenceFailure`] receives the same projection because its `detail`
/// retains the raw provider text for in-process policy only.
pub(crate) fn safe_inference_error_detail(err: &anyhow::Error) -> Option<SafeProviderDetail> {
    err.chain().find_map(|cause| {
        cause
            .downcast_ref::<InferenceFailure>()
            .map(safe_provider_detail)
            .or_else(|| {
                cause
                    .downcast_ref::<rig::completion::CompletionError>()
                    .map(safe_completion_error_detail)
            })
    })
}

/// Longest provider-authored message the user-facing inline error carries.
const MAX_USER_PROVIDER_MESSAGE_CHARS: usize = 300;
/// Longest provider error `code` token accepted for display.
const MAX_USER_PROVIDER_CODE_BYTES: usize = 64;
/// Opaque token-like runs at least this long are masked before display: a
/// provider may echo a key, request signature, or account token that the
/// redaction table does not know about.
const MIN_MASKED_OPAQUE_RUN_CHARS: usize = 40;
/// JSON candidates tried while looking for the provider's error envelope.
const MAX_ERROR_ENVELOPE_CANDIDATES: usize = 8;

/// User-facing projection of a terminal failure's provider error, for the
/// UI-only `InferenceFailed` event and nothing else (#551).
///
/// The fail-closed funnel ([`safe_provider_detail`]) still governs every sink
/// that persists, audits, reports to a parent agent, or can reach model
/// context; those keep the fixed [`PROVIDER_DETAIL_OMITTED`] marker. The inline
/// red error is the one surface a human reads, and an opaque marker there makes
/// a bad key or a mistyped model id undiagnosable. This projection therefore
/// shows the provider's *structured* `error.message` / `error.code` only:
///
/// * the raw body is never shown: only those two fields of a JSON error
///   envelope are read (OpenRouter's wrapped `metadata.raw` upstream envelope
///   is unwrapped the same way); a non-JSON body yields the marker;
/// * the code is accepted only as a short `[A-Za-z0-9_.:-]` token or a number;
/// * control characters (terminal escapes included) are removed, whitespace is
///   collapsed, opaque token-like runs are masked, and the message is bounded;
/// * the result is scrubbed through the session redaction table (the daemon
///   event boundary scrubs it again).
pub fn user_facing_provider_error(
    failure: &InferenceFailure,
    redact: &crate::redact::RedactionTable,
) -> String {
    let Some((message, code)) = provider_error_envelope(&failure.detail) else {
        return PROVIDER_DETAIL_OMITTED.to_string();
    };
    // Redaction runs on each COMPLETE field before any transformation:
    // truncating or masking first could split a registered secret so its
    // remainder no longer matches the table (review C1). The enforced view
    // is used because owner event delivery has no later scrub.
    let table = redact.enforced();
    let message = message
        .map(|message| table.scrub(&message))
        .map(|message| sanitize_provider_text(&message))
        .filter(|message| !message.is_empty());
    // A code is shown only when it still looks like a semantic error code
    // after scrubbing; opaque or token-like values are dropped (review C2).
    let code = code
        .map(|code| table.scrub(&code))
        .filter(|code| semantic_error_code(code))
        .filter(|code| {
            Some(code.as_str()) != failure.observed_status.map(|s| s.to_string()).as_deref()
        });
    let text = match (message, code) {
        (Some(message), Some(code)) => format!("{message} [{code}]"),
        (Some(message), None) => message,
        (None, Some(code)) => format!("[{code}]"),
        (None, None) => return PROVIDER_DETAIL_OMITTED.to_string(),
    };
    // Bound the final projection, then scrub once more as defense in depth.
    table.scrub(&bound_chars(&text, MAX_USER_PROVIDER_MESSAGE_CHARS))
}

/// Longest `-`/`_`/`.`/`:`-separated segment a displayed error code may have.
/// Real codes (`invalid_function_parameters`, `model_not_found`, `1113`) are
/// short words; a long segment is an opaque token, never a category.
const MAX_ERROR_CODE_SEGMENT_CHARS: usize = 24;

fn semantic_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_USER_PROVIDER_CODE_BYTES
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
        && code
            .split(['_', '.', ':', '-'])
            .all(|segment| segment.len() <= MAX_ERROR_CODE_SEGMENT_CHARS)
}

fn bound_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out = text.chars().take(max - 1).collect::<String>();
    out.push('…');
    out
}

/// `(error.message, error.code)` from the first JSON error envelope embedded
/// in `detail`. Rig renders an HTTP failure as `... with message: {body}`, so
/// the envelope is located by trying the first few `{` offsets.
fn provider_error_envelope(detail: &str) -> Option<(Option<String>, Option<String>)> {
    detail
        .match_indices('{')
        .take(MAX_ERROR_ENVELOPE_CANDIDATES)
        .find_map(|(offset, _)| {
            let value = serde_json::Deserializer::from_str(&detail[offset..])
                .into_iter::<serde_json::Value>()
                .next()?
                .ok()?;
            envelope_fields(&value)
        })
}

fn envelope_fields(value: &serde_json::Value) -> Option<(Option<String>, Option<String>)> {
    let object = value.as_object()?;
    let error = match object.get("error") {
        Some(serde_json::Value::Object(error)) => error,
        // `{"error": "text", "code": ...}` (xAI and others).
        Some(serde_json::Value::String(message)) => {
            return Some((Some(message.clone()), error_code(object.get("code"))));
        }
        _ => object,
    };
    let mut message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let mut code = error_code(error.get("code")).or_else(|| error_code(error.get("type")));
    // OpenRouter wraps the routed provider's own envelope as a JSON string in
    // `metadata.raw` behind a generic "Provider returned error" message.
    if let Some(raw) = error
        .get("metadata")
        .and_then(|metadata| metadata.get("raw"))
        .and_then(serde_json::Value::as_str)
        && let Ok(inner) = serde_json::from_str::<serde_json::Value>(raw)
        && let Some((inner_message, inner_code)) = envelope_fields(&inner)
    {
        if inner_message.is_some() {
            message = inner_message;
        }
        if inner_code.is_some() {
            code = inner_code;
        }
    }
    (message.is_some() || code.is_some()).then_some((message, code))
}

/// The raw code field; validation happens after redaction in
/// [`user_facing_provider_error`].
fn error_code(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::String(code) if !code.is_empty() => Some(code.clone()),
        _ => None,
    }
}

/// Control characters removed, whitespace collapsed, opaque runs masked, and
/// the result bounded to [`MAX_USER_PROVIDER_MESSAGE_CHARS`].
fn sanitize_provider_text(raw: &str) -> String {
    let flattened = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();
    let mut out = String::new();
    for word in flattened.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&mask_opaque_runs(word));
    }
    if out.chars().count() > MAX_USER_PROVIDER_MESSAGE_CHARS {
        out = out
            .chars()
            .take(MAX_USER_PROVIDER_MESSAGE_CHARS - 1)
            .collect::<String>();
        out.push('…');
    }
    out
}

fn mask_opaque_runs(word: &str) -> String {
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.chars().count() >= MIN_MASKED_OPAQUE_RUN_CHARS {
            out.push('…');
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in word.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '=') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Log a best-effort utility-model failure without formatting provider-owned
/// completion errors. Non-inference control/configuration errors keep their
/// useful internal diagnostic; provider errors are reduced to the same fixed
/// marker and typed metadata used by durable and user-visible failure paths.
pub(crate) fn log_utility_model_failure(operation: &'static str, err: &anyhow::Error) {
    if let Some(safe) = safe_inference_error_detail(err) {
        tracing::debug!(
            operation,
            provider_detail = safe.marker,
            observed_status = ?safe.observed_status,
            recovery = safe.recovery.as_str(),
            "utility model call failed"
        );
    } else {
        tracing::debug!(operation, error = %err, "utility model call failed");
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("inference failed ({class}) for {provider}/{model} after {elapsed_ms}ms at phase {phase}")]
pub struct InferenceFailure {
    pub provider: String,
    pub model: String,
    pub phase: String,
    pub class: InferenceErrorClass,
    pub elapsed_ms: u64,
    pub retry_attempts: u32,
    /// Human-readable underlying reason (the source error's message), shown
    /// in the inline error alongside provider/model. Empty for a pure
    /// timeout (the class + ceiling already say everything).
    pub detail: String,
    /// The observed HTTP status the provider returned, retained SEPARATELY from
    /// `class` (issue #23). A billing/overload class does not embed its status;
    /// this preserves it for diagnostics (e.g. a billing failure observed as
    /// `429`). `None` when no HTTP status was observed (pure timeout / transport
    /// failure / pre-dispatch prep error).
    pub observed_status: Option<u16>,
    /// The typed provider-recovery signal parsed from the error body. Drives the
    /// billing-fail-fast-cross-provider-only and overload-one-retry-then-
    /// cross-provider policies; [`ProviderRecoverySignal::None`] for every
    /// ordinary failure.
    pub recovery: ProviderRecoverySignal,
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

    if super::rig_boundary::is_oauth_expired_detail(&failure.detail) {
        return Some(AuthFailureKind::OAuthExpired {
            provider: failure.provider.clone(),
        });
    }
    if let InferenceErrorClass::MissingToolEntitlement { feature } = &failure.class {
        return Some(AuthFailureKind::MissingEntitlement {
            feature: feature.clone(),
        });
    }
    if matches!(failure.class, InferenceErrorClass::ProviderNotConfigured) {
        return Some(AuthFailureKind::ProviderNotConfigured);
    }
    match failure.class.provider_status() {
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
pub fn failure_engages_backup(class: &InferenceErrorClass) -> bool {
    match class {
        InferenceErrorClass::TimeoutTtft
        | InferenceErrorClass::TimeoutIdle
        | InferenceErrorClass::Network
        | InferenceErrorClass::MissingToolEntitlement { .. }
        | InferenceErrorClass::ClientSideToolsUnsupported
        // Billing/account-quota exhaustion DOES engage backup — but only a
        // DIFFERENT PROVIDER can answer (the same provider's account is
        // exhausted). `turn_with_backup` filters candidates to a different
        // provider for a `ProviderRecoverySignal::BillingExhausted` failure; a
        // same-provider backup is never tried for billing.
        | InferenceErrorClass::BillingOrQuotaExhausted => true,
        InferenceErrorClass::Http(status) => (500..=599).contains(status),
        InferenceErrorClass::UtilityTimeout
        | InferenceErrorClass::ResponsesToolIdentity
        | InferenceErrorClass::ProviderNotConfigured
        | InferenceErrorClass::ProviderRateLimit
        // A non-renderable wire field fails the same way on any untrusted
        // target, so a different model cannot answer it — hard-fail, no backup.
        | InferenceErrorClass::UnrenderableWireField
        | InferenceErrorClass::Other(_) => false,
    }
}

/// Per-turn phase timings for a *successful* inference, in milliseconds from
/// dispatch (implementation note #5).
/// The dispatch instant is the zero point; `first_token_ms` is `None` when
/// the stream produced no chunk before finishing (a rare empty completion).
/// Recorded into the dispatch-time record's terminal payload so an export
/// answers "how long to first token / total" as a lookup. The failure path
/// carries its own elapsed-ms on [`InferenceFailure`].
#[derive(Debug, Default)]
pub struct InferenceTiming {
    /// Milliseconds from dispatch to the first streamed chunk, if any.
    pub first_token_ms: Option<u64>,
    /// Milliseconds from dispatch to stream completion.
    pub completed_ms: u64,
    /// Open display-stream classifier for the successful attempt, when the
    /// production display path constructed one at attempt dispatch. The
    /// turn-phase layer calls [`DisplayStreamClassifier::finish`] after
    /// translation so the durable snapshot measures displayed UX text.
    pub open_display: Option<crate::engine::response_performance::DisplayStreamClassifier>,
}

/// Persist a self-healed wire-API endpoint back into config
/// (implementation note): record `resolved` (a concrete
/// `completions`/`responses`, never `auto`) onto the `(provider_id, model_id)`
/// model entry with `recovered` provenance, reusing the same read-modify-write
/// `ConfigDoc` path that caches the fetched `/models` list. This preserves the
/// working fallback when no catalog can name the endpoint, while letting a
/// later live catalog supersede stale learned state. A user endpoint pin is
/// never overwritten. When the model isn't yet listed in config (e.g. a
/// manually-typed id never fetched) the entry is created so the learned value
/// survives the next `/models` refresh.
/// Best-effort: a self-heal that can't be persisted still served the turn
/// correctly, so any IO error is logged, never propagated into the live turn.
pub(super) fn persist_wire_api(
    config_path: &Path,
    provider_id: &str,
    model_id: &str,
    resolved: crate::config::providers::WireApi,
) {
    use crate::config::providers::{ConfigDoc, ModelEntry, WireApiProvenance};
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
        if !model.wire_api.is_auto() && model.wire_api_provenance.is_user_configured() {
            return;
        }
        if model.wire_api == resolved
            && matches!(model.wire_api_provenance, WireApiProvenance::Recovered)
        {
            return; // already pinned — no write.
        }
        model.wire_api = resolved;
        model.wire_api_provenance = WireApiProvenance::Recovered;
    } else {
        entry.models.push(ModelEntry {
            id: model_id.to_string(),
            wire_api: resolved,
            wire_api_provenance: WireApiProvenance::Recovered,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_anyhow_projection_omits_provider_request_id() {
        const SENTINEL: &str = "provider-request-id-must-not-reach-log-fields";
        let raw = rig::completion::CompletionError::ProviderResponse(
            rig::ProviderResponseError::new(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                "insufficient balance",
            )
            .with_provider_request_id(Some(SENTINEL.to_string())),
        );

        assert!(raw.to_string().contains(SENTINEL));
        let wrapped = anyhow::Error::new(raw).context("utility model send failed");
        let safe = safe_inference_error_detail(&wrapped).expect("provider error projection");
        let rendered = serde_json::to_string(&safe).expect("safe projection serializes");
        assert!(
            !rendered.contains(SENTINEL),
            "safe projection leaked: {rendered}"
        );
        assert_eq!(safe.marker, PROVIDER_DETAIL_OMITTED);
        assert_eq!(safe.observed_status, Some(429));
        assert_eq!(safe.recovery, ProviderRecoverySignal::BillingExhausted);
    }

    fn http_failure(status: u16, body: &str) -> InferenceFailure {
        let err = rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(
                reqwest::StatusCode::from_u16(status).unwrap(),
                body.to_string(),
            ),
        );
        InferenceFailure {
            provider: "openrouter".into(),
            model: "deepseek/deepseek-v9-doesnotexist".into(),
            phase: "dispatched".into(),
            class: InferenceErrorClass::Http(status),
            elapsed_ms: 1,
            retry_attempts: 0,
            detail: err.to_string(),
            observed_status: Some(status),
            recovery: ProviderRecoverySignal::None,
        }
    }

    /// #551: the inline error shows the provider's structured message, not
    /// the opaque marker — and nothing else from the body (`user_id`).
    #[test]
    fn user_facing_error_shows_structured_provider_message_only() {
        let failure = http_failure(
            400,
            r#"{"error":{"message":"deepseek/deepseek-v9-doesnotexist is not a valid model ID","code":400},"user_id":"user_2abcdefSECRETUSER"}"#,
        );
        let shown = user_facing_provider_error(&failure, &crate::redact::RedactionTable::empty());
        assert_eq!(
            shown,
            "deepseek/deepseek-v9-doesnotexist is not a valid model ID"
        );
        // The persisted/audit funnel is unchanged: still the fixed marker.
        assert_eq!(
            safe_provider_detail(&failure).marker,
            PROVIDER_DETAIL_OMITTED
        );
    }

    #[test]
    fn user_facing_error_unwraps_openrouter_upstream_envelope() {
        let raw = serde_json::json!({
            "error": {
                "message": "Invalid schema for function 'task': 'propertyNames' is not permitted.",
                "type": "invalid_request_error",
                "code": "invalid_function_parameters",
                "param": "tools[21].parameters"
            }
        })
        .to_string();
        let body = serde_json::json!({
            "error": {
                "message": "Provider returned error",
                "code": 400,
                "metadata": {"raw": raw, "provider_name": "OpenAI"}
            }
        })
        .to_string();
        let shown = user_facing_provider_error(
            &http_failure(400, &body),
            &crate::redact::RedactionTable::empty(),
        );
        assert_eq!(
            shown,
            "Invalid schema for function 'task': 'propertyNames' is not permitted. [invalid_function_parameters]"
        );
    }

    /// The projection never relaxes the secret boundary: known secrets are
    /// scrubbed, unknown opaque tokens are masked, terminal escapes are
    /// stripped, and a non-JSON body yields the marker.
    #[test]
    fn user_facing_error_scrubs_masks_and_fails_closed() {
        const KNOWN: &str = "known-session-secret-value-1234567890";
        const UNKNOWN_KEY: &str =
            "opaque_token_fixture_0123456789abcdef0123456789abcdef01234567";
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(KNOWN.to_string(), "test".into())
            .unwrap();
        let body = serde_json::json!({
            "error": {
                "message": format!("bad key {UNKNOWN_KEY} for \u{1b}[31maccount {KNOWN}\u{7}"),
                "code": "invalid_api_key"
            }
        })
        .to_string();
        let shown = user_facing_provider_error(&http_failure(401, &body), &table);
        assert!(!shown.contains(KNOWN), "{shown}");
        assert!(!shown.contains(UNKNOWN_KEY), "{shown}");
        assert!(
            !shown.contains('\u{1b}') && !shown.contains('\u{7}'),
            "{shown:?}"
        );
        assert!(shown.starts_with("bad key … for"), "{shown}");
        assert!(shown.ends_with("[invalid_api_key]"), "{shown}");

        let plain = user_facing_provider_error(
            &http_failure(502, "<html>Bad Gateway SECRET</html>"),
            &table,
        );
        assert_eq!(plain, PROVIDER_DETAIL_OMITTED);

        let bounded = user_facing_provider_error(
            &http_failure(
                400,
                &serde_json::json!({"error": {"message": "word ".repeat(400)}}).to_string(),
            ),
            &table,
        );
        assert_eq!(bounded.chars().count(), MAX_USER_PROVIDER_MESSAGE_CHARS);
    }

    /// Review C1: a registered secret is scrubbed as a whole literal before
    /// truncation or opaque-run masking could split it.
    #[test]
    fn user_facing_error_redacts_registered_secrets_before_transforming() {
        const CROSSING: &str = "registered-credential-crossing-cutoff-0042";
        let masked_inside = format!("prefix{}/private-fragment", "a".repeat(50));
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(CROSSING.to_string(), "test".into())
            .unwrap()
            .with_forced_literal(masked_inside.clone(), "test".into())
            .unwrap();
        let near_cutoff = format!("{} {CROSSING}", "x".repeat(280));
        let shown = user_facing_provider_error(
            &http_failure(
                401,
                &serde_json::json!({"error": {"message": near_cutoff}}).to_string(),
            ),
            &table,
        );
        assert!(!shown.contains("registered-credential"), "{shown}");
        assert!(
            shown.chars().count() <= MAX_USER_PROVIDER_MESSAGE_CHARS,
            "{shown}"
        );
        let shown = user_facing_provider_error(
            &http_failure(
                401,
                &serde_json::json!({"error": {"message": format!("echo {masked_inside}")}})
                    .to_string(),
            ),
            &table,
        );
        assert!(!shown.contains("private-fragment"), "{shown}");
    }

    /// Review C2: `error.code` is shown only as a short semantic token; an
    /// opaque credential-shaped code is dropped, never emitted verbatim.
    #[test]
    fn user_facing_error_drops_opaque_codes() {
        const OPAQUE: &str = "opaque_token_fixture_0123456789abcdef0123456789ab";
        let table = crate::redact::RedactionTable::empty();
        let shown = user_facing_provider_error(
            &http_failure(
                401,
                &serde_json::json!({"error": {"message": "denied", "code": OPAQUE}}).to_string(),
            ),
            &table,
        );
        assert_eq!(shown, "denied");
        let shown = user_facing_provider_error(
            &http_failure(
                400,
                &serde_json::json!({"error": {"message": "nope", "code": "model_not_found"}})
                    .to_string(),
            ),
            &table,
        );
        assert_eq!(shown, "nope [model_not_found]");
    }
}
