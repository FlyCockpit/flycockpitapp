use super::*;

pub use crate::daemon::proto::InferenceErrorClass;

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
    pub class: InferenceErrorClass,
    pub elapsed_ms: u64,
    pub retry_attempts: u32,
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
        | InferenceErrorClass::ClientSideToolsUnsupported => true,
        InferenceErrorClass::Http(status) => (500..=599).contains(status),
        InferenceErrorClass::UtilityTimeout
        | InferenceErrorClass::ResponsesToolIdentity
        | InferenceErrorClass::ProviderNotConfigured
        | InferenceErrorClass::ProviderRateLimit
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
#[derive(Debug, Clone, Copy, Default)]
pub struct InferenceTiming {
    /// Milliseconds from dispatch to the first streamed chunk, if any.
    pub first_token_ms: Option<u64>,
    /// Milliseconds from dispatch to stream completion.
    pub completed_ms: u64,
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
