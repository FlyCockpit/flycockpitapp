use super::failure::{InferenceErrorClass, ProviderRecoverySignal};

/// The provider error `code` that signals a model is not served over the
/// endpoint that was tried. Used by both inference-time endpoint recovery and
/// provider probing so the two call sites cannot drift.
pub(crate) const UNSUPPORTED_API_CODE: &str = "unsupported_api_for_model";

const STREAM_TIMEOUT_TTFT: &str = "timeout_ttft";
const STREAM_TIMEOUT_IDLE: &str = "timeout_idle";

/// Sentinel embedded in a [`rig::completion::CompletionError`] carrying a
/// stream-timeout verdict so it crosses the retry boundary fail-fast. Distinct
/// from [`AttemptCancelled`] so `complete_captured` can map it to a typed
/// timeout [`InferenceErrorClass`].
#[derive(Debug, thiserror::Error)]
#[error("inference stream timed out ({0})")]
struct StreamTimeout(&'static str);

/// Build the TTFT-timeout sentinel as a `CompletionError`.
pub(crate) fn ttft_timeout() -> rig::completion::CompletionError {
    rig::completion::CompletionError::RequestError(Box::new(StreamTimeout(STREAM_TIMEOUT_TTFT)))
}

/// Build the idle-timeout sentinel as a `CompletionError`.
pub(crate) fn idle_timeout() -> rig::completion::CompletionError {
    rig::completion::CompletionError::RequestError(Box::new(StreamTimeout(STREAM_TIMEOUT_IDLE)))
}

/// Detect the [`StreamTimeout`] sentinel, returning its kind tag when present.
pub(crate) fn stream_timeout_kind(err: &rig::completion::CompletionError) -> Option<&'static str> {
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

/// Classify a terminal [`rig::completion::CompletionError`] into the failure
/// taxonomy recorded on the event + dispatch-time record.
pub(crate) fn classify_inference_failure(
    err: &rig::completion::CompletionError,
) -> InferenceErrorClass {
    if let Some(kind) = stream_timeout_kind(err) {
        return match kind {
            STREAM_TIMEOUT_TTFT => InferenceErrorClass::TimeoutTtft,
            _ => InferenceErrorClass::TimeoutIdle,
        };
    }
    if let Some(status) = http_status_of(err) {
        return InferenceErrorClass::Http(status);
    }
    InferenceErrorClass::Network
}

/// Extract the HTTP status code an error carries, if any. Direct rig HTTP
/// status variants win. Provider prose uses one shared policy: first accept
/// rig's stable `Invalid status code ` prefix, then fall back to a deliberately
/// bounded marker scan that only recognizes retry-relevant provider statuses.
/// This keeps arbitrary body digits from becoming an HTTP status while
/// preserving retry's historical coverage for provider strings like `HTTP 503`.
pub(crate) fn http_status_of(err: &rig::completion::CompletionError) -> Option<u16> {
    if let rig::completion::CompletionError::ProviderError(message) = err {
        return provider_error_status(message);
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

pub(crate) fn provider_error_status(msg: &str) -> Option<u16> {
    if let Some(status) = invalid_status_code_prefix_status(msg) {
        return Some(status);
    }
    provider_error_marker_status(msg)
}

fn invalid_status_code_prefix_status(msg: &str) -> Option<u16> {
    let digits = msg
        .strip_prefix("Invalid status code ")?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits
        .parse::<u16>()
        .ok()
        .filter(|status| (100..=599).contains(status))
}

fn provider_error_marker_status(msg: &str) -> Option<u16> {
    let lower = msg.to_ascii_lowercase();
    for marker in ["status", "http", "code", "error"] {
        if let Some(status) = status_after_marker(&lower, marker)
            && is_provider_status_marker_candidate(status)
        {
            return Some(status);
        }
    }
    if lower.contains("service unavailable") {
        return Some(503);
    }
    None
}

fn status_after_marker(lower: &str, marker: &str) -> Option<u16> {
    let idx = lower.find(marker)?;
    let rest = &lower[idx + marker.len()..];
    let start = rest.find(|c: char| c.is_ascii_digit())?;
    let digits: String = rest[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .take(3)
        .collect();
    if digits.len() == 3 {
        digits.parse::<u16>().ok()
    } else {
        None
    }
}

fn is_provider_status_marker_candidate(status: u16) -> bool {
    status == 429 || status == 503
}

pub(crate) fn provider_error_status_for_retry(
    err: &rig::completion::CompletionError,
) -> Option<u16> {
    match err {
        rig::completion::CompletionError::ProviderError(message) => provider_error_status(message),
        _ => None,
    }
}

fn is_unsupported_api_error(err: &rig::completion::CompletionError) -> bool {
    match err {
        rig::completion::CompletionError::ProviderError(msg) => msg.contains(UNSUPPORTED_API_CODE),
        rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(status, body),
        ) => status.as_u16() == 400 && body.contains(UNSUPPORTED_API_CODE),
        _ => false,
    }
}

pub(crate) fn is_endpoint_mismatch_error(err: &rig::completion::CompletionError) -> bool {
    if is_unsupported_api_error(err) {
        return true;
    }
    match err {
        rig::completion::CompletionError::ProviderError(msg) => {
            is_endpoint_mismatch_error_text(msg)
        }
        rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(status, body),
        ) => {
            let code = status.as_u16();
            if code == 404 || code == 405 || (code == 400 && body.contains(UNSUPPORTED_API_CODE)) {
                return true;
            }
            is_endpoint_mismatch_error_text(body)
        }
        rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCode(status),
        ) => matches!(status.as_u16(), 404 | 405),
        _ => false,
    }
}

pub(crate) fn is_endpoint_mismatch_error_text(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("method not allowed")
        || lower.contains("unknown route")
        || lower.contains("unknown path")
        || lower.contains("unknown endpoint")
        || lower.contains("no route")
        || lower.contains("no path")
        || lower.contains("route not found")
        || lower.contains("path not found")
        || lower.contains("endpoint not found")
        || lower.contains("use the responses api")
        || lower.contains("use /v1/responses")
        || lower.contains(UNSUPPORTED_API_CODE)
        || lower.contains("not supported on this endpoint")
        || lower.contains("not supported with this endpoint")
        || lower.contains("chat completions endpoint")
        || lower.contains("/chat/completions endpoint")
        || lower.contains("responses endpoint")
        || lower.contains("unsupported endpoint")
}

/// Parse the typed provider-recovery signal from a terminal completion error's
/// body (issue #23). Centralized here at the model boundary so retry, failover,
/// and the persisted failure record all read ONE classification (never
/// re-derived in a driver/agent path). Case-insensitive over the error's display
/// text; the closed sets are the ONLY signals — no fuzzy `quota` / `unavailable`
/// matching. Billing takes precedence over overload when both appear.
pub(crate) fn provider_recovery_signal(
    err: &rig::completion::CompletionError,
) -> ProviderRecoverySignal {
    provider_recovery_signal_from_text(&recovery_scan_text(err))
}

/// The provider body text a recovery signal is scanned from. A `ProviderError`
/// string and a status-with-message HTTP error carry the raw body directly;
/// every other variant falls back to its Display (which never carries a body a
/// signal would hide in).
fn recovery_scan_text(err: &rig::completion::CompletionError) -> String {
    match err {
        rig::completion::CompletionError::ProviderError(msg) => msg.clone(),
        rig::completion::CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(_, msg),
        ) => msg.clone(),
        other => other.to_string(),
    }
}

/// A fully classified terminal failure: the semantic error class, the observed
/// HTTP status retained SEPARATELY, and the typed provider-recovery signal.
/// Billing overrides the class to `BillingOrQuotaExhausted` (its observed status
/// — often `429` — is preserved on `observed_status`, never stuffed into the
/// class). Overload keeps its natural HTTP/network class; the recovery signal
/// distinguishes it from a status-only failure for the retry/failover policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClassifiedFailure {
    pub class: InferenceErrorClass,
    pub observed_status: Option<u16>,
    pub recovery: ProviderRecoverySignal,
}

/// Classify a terminal completion error at the model boundary — the SINGLE
/// production path that maps a raw error into `(class, observed_status,
/// recovery)`. Both the live dispatch record and the retry/failover policy read
/// from here so the classification is never re-derived elsewhere.
pub(crate) fn classify_terminal_failure(
    err: &rig::completion::CompletionError,
) -> ClassifiedFailure {
    classify_terminal_failure_with_floor(err, ProviderRecoverySignal::None)
}

/// As [`classify_terminal_failure`], but the terminal recovery signal is the
/// STRONGER of this error's own signal and `floor` — the strongest signal
/// observed across the whole retry chain (issue #23). This prevents a later
/// generic error (e.g. a 500 on the retry) from masking an earlier billing or
/// overload signal; a billing floor also overrides the class to
/// `BillingOrQuotaExhausted`.
pub(crate) fn classify_terminal_failure_with_floor(
    err: &rig::completion::CompletionError,
    floor: ProviderRecoverySignal,
) -> ClassifiedFailure {
    let own = provider_recovery_signal(err);
    let recovery = if floor.rank() > own.rank() {
        floor
    } else {
        own
    };
    let observed_status = http_status_of(err);
    let base = classify_inference_failure(err);
    let class = match recovery {
        ProviderRecoverySignal::BillingExhausted => InferenceErrorClass::BillingOrQuotaExhausted,
        ProviderRecoverySignal::Overloaded | ProviderRecoverySignal::None => base,
    };
    ClassifiedFailure {
        class,
        observed_status,
        recovery,
    }
}

pub(crate) fn provider_recovery_signal_from_text(text: &str) -> ProviderRecoverySignal {
    let lower = text.to_ascii_lowercase();
    if billing_signal_present(&lower) {
        return ProviderRecoverySignal::BillingExhausted;
    }
    if lower.contains("server_is_overloaded") || lower.contains("service_unavailable_error") {
        return ProviderRecoverySignal::Overloaded;
    }
    ProviderRecoverySignal::None
}

/// The closed, case-insensitive billing/quota-exhaustion set (already lowered).
fn billing_signal_present(lower: &str) -> bool {
    lower.contains("insufficient balance")
        || lower.contains("no resource package")
        || lower.contains("please recharge")
        || lower.contains("exceeded your current quota")
        || lower.contains("billing hard limit")
        || contains_structured_code_1113(lower)
}

/// Whether the structured provider error code `1113` appears as a standalone
/// token — never glued to a longer number (`11130` / `211137`) or an adjacent
/// word (`error1113` / `1113suffix`). Neighboring ASCII alphanumerics on either
/// side disqualify the match, so only a genuinely delimited `1113` counts.
fn contains_structured_code_1113(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find("1113") {
        let start = search_from + rel;
        let end = start + 4;
        let boundary_before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let boundary_after = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if boundary_before && boundary_after {
            return true;
        }
        search_from = start + 1;
    }
    false
}

/// Human-readable detail for the inline error. A pure timeout needs none; a
/// network / HTTP failure carries the underlying message.
pub(crate) fn failure_detail(
    err: &rig::completion::CompletionError,
    class: &InferenceErrorClass,
) -> String {
    match class {
        InferenceErrorClass::TimeoutTtft | InferenceErrorClass::TimeoutIdle => String::new(),
        _ => err.to_string(),
    }
}

pub(crate) fn is_oauth_expired_detail(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("subscription auth expired")
        || detail.contains("oauth token expired")
        || detail.contains("oauth credential expired")
        || detail.contains("oauth token was revoked")
}

pub(crate) fn provider_rejected_xai_multi_agent_tools(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("client-side tools")
        && detail.contains("multi-agent")
        && detail.contains("beta access")
}

/// Sentinel embedded in a [`rig::completion::CompletionError`] when a retry
/// attempt is aborted by ctrl+c.
#[derive(Debug, thiserror::Error)]
#[error("inference attempt cancelled by user")]
struct AttemptCancelled;

/// Build the cancellation sentinel as a `CompletionError`.
pub(crate) fn attempt_cancelled() -> rig::completion::CompletionError {
    rig::completion::CompletionError::RequestError(Box::new(AttemptCancelled))
}

/// Detect the [`AttemptCancelled`] sentinel in a `CompletionError`.
pub(crate) fn is_attempt_cancelled(err: &rig::completion::CompletionError) -> bool {
    if let rig::completion::CompletionError::RequestError(inner) = err {
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rig::completion::CompletionError;

    use super::*;
    use crate::engine::model::{
        InferenceFailure, ProviderRecoverySignal, auth_failure_kind, failure_engages_backup,
    };

    fn provider_error(message: &str) -> CompletionError {
        CompletionError::ProviderError(message.to_string())
    }

    #[test]
    fn error_taxonomy_as_str_is_unchanged_for_every_existing_value() {
        let cases = [
            (InferenceErrorClass::TimeoutTtft, "timeout_ttft"),
            (InferenceErrorClass::TimeoutIdle, "timeout_idle"),
            (InferenceErrorClass::Network, "network"),
            (InferenceErrorClass::Http(502), "http_502"),
            (InferenceErrorClass::UtilityTimeout, "utility_timeout"),
            (
                InferenceErrorClass::MissingToolEntitlement {
                    feature: "client_side_tools".to_string(),
                },
                "missing_tool_entitlement",
            ),
            (
                InferenceErrorClass::ClientSideToolsUnsupported,
                "client_side_tools_unsupported",
            ),
            (
                InferenceErrorClass::ResponsesToolIdentity,
                "responses_tool_identity",
            ),
            (
                InferenceErrorClass::ProviderNotConfigured,
                "provider_not_configured",
            ),
        ];
        for (class, expected) in cases {
            assert_eq!(class.as_str(), expected);
        }
    }

    #[test]
    fn error_taxonomy_round_trips_every_variant() {
        let cases = [
            InferenceErrorClass::TimeoutTtft,
            InferenceErrorClass::TimeoutIdle,
            InferenceErrorClass::Network,
            InferenceErrorClass::Http(599),
            InferenceErrorClass::UtilityTimeout,
            InferenceErrorClass::MissingToolEntitlement {
                feature: "client_side_tools".to_string(),
            },
            InferenceErrorClass::ClientSideToolsUnsupported,
            InferenceErrorClass::ResponsesToolIdentity,
            InferenceErrorClass::ProviderNotConfigured,
            InferenceErrorClass::ProviderRateLimit,
            InferenceErrorClass::BillingOrQuotaExhausted,
            InferenceErrorClass::UnrenderableWireField,
            InferenceErrorClass::Other("novel_provider_class".to_string()),
        ];
        for class in cases {
            let parsed = InferenceErrorClass::from_str(&class.as_str()).unwrap();
            assert_eq!(parsed, class);
        }
    }

    #[test]
    fn error_taxonomy_missing_entitlement_display_string_stays_flat() {
        let class = InferenceErrorClass::MissingToolEntitlement {
            feature: "xai_multi_agent_tools_beta".to_string(),
        };
        assert_eq!(class.as_str(), "missing_tool_entitlement");
        assert_eq!(
            InferenceErrorClass::from_str(&class.as_str()).unwrap(),
            InferenceErrorClass::MissingToolEntitlement {
                feature: "client_side_tools".to_string()
            }
        );
    }

    #[test]
    fn error_taxonomy_unknown_class_maps_to_other_not_network() {
        assert_eq!(
            InferenceErrorClass::from_str("novel_provider_failure").unwrap(),
            InferenceErrorClass::Other("novel_provider_failure".to_string())
        );
    }

    #[test]
    fn error_taxonomy_backup_engagement_set_is_unchanged() {
        let cases = [
            (InferenceErrorClass::TimeoutTtft, true),
            (InferenceErrorClass::TimeoutIdle, true),
            (InferenceErrorClass::Network, true),
            (
                InferenceErrorClass::MissingToolEntitlement {
                    feature: "client_side_tools".to_string(),
                },
                true,
            ),
            (InferenceErrorClass::ClientSideToolsUnsupported, true),
            (InferenceErrorClass::Http(500), true),
            (InferenceErrorClass::Http(502), true),
            (InferenceErrorClass::Http(599), true),
            (InferenceErrorClass::Http(400), false),
            (InferenceErrorClass::Http(401), false),
            (InferenceErrorClass::Http(403), false),
            (InferenceErrorClass::Http(404), false),
            (InferenceErrorClass::Http(429), false),
            (InferenceErrorClass::Other("http_".to_string()), false),
            (InferenceErrorClass::Other("weird".to_string()), false),
            (InferenceErrorClass::Other("http_abc".to_string()), false),
        ];
        for (class, expected) in cases {
            assert_eq!(failure_engages_backup(&class), expected, "{class:?}");
        }
    }

    #[test]
    fn error_taxonomy_retry_decision_matches_previous_string_behavior() {
        let cases = [
            (
                InferenceErrorClass::TimeoutTtft,
                None,
                ("fail_fast", "time_to_first_token_timeout"),
            ),
            (
                InferenceErrorClass::TimeoutIdle,
                None,
                ("fail_fast", "stream_idle_timeout"),
            ),
            (
                InferenceErrorClass::Network,
                None,
                (
                    "terminal_after_retry_layer",
                    "transport_or_provider_failure_after_retry_layer",
                ),
            ),
            (
                InferenceErrorClass::MissingToolEntitlement {
                    feature: "client_side_tools".to_string(),
                },
                None,
                ("fail_fast", "client_side_capability_block"),
            ),
            (
                InferenceErrorClass::ClientSideToolsUnsupported,
                None,
                ("fail_fast", "client_side_capability_block"),
            ),
            (
                InferenceErrorClass::Http(429),
                Some(429),
                (
                    "terminal_after_retry_layer",
                    "retryable_http_status_terminal",
                ),
            ),
            (
                InferenceErrorClass::Http(502),
                Some(502),
                ("terminal_after_retry_layer", "server_http_status_terminal"),
            ),
            (
                InferenceErrorClass::Http(400),
                Some(400),
                ("fail_fast", "non_retryable_http_status"),
            ),
            (
                InferenceErrorClass::Other("weird".to_string()),
                None,
                ("fail_fast", "non_retryable_or_unclassified_failure"),
            ),
        ];
        for (class, provider_status, expected) in cases {
            assert_eq!(
                crate::engine::retry::failure_retry_decision_and_rationale(&class, provider_status),
                expected,
                "{class:?}"
            );
        }
    }

    #[test]
    fn error_taxonomy_missing_entitlement_feature_comes_from_the_type() {
        let failure = InferenceFailure {
            provider: "grok-oauth".to_string(),
            model: "grok-multi-agent".to_string(),
            phase: "prep".to_string(),
            class: InferenceErrorClass::MissingToolEntitlement {
                feature: "xai_multi_agent_tools_beta".to_string(),
            },
            elapsed_ms: 0,
            retry_attempts: 1,
            detail: "client-side tools require entitlement `wrong_feature`".to_string(),
            observed_status: None,
            recovery: ProviderRecoverySignal::None,
        };
        assert_eq!(
            auth_failure_kind(&failure),
            Some(crate::daemon::proto::AuthFailureKind::MissingEntitlement {
                feature: "xai_multi_agent_tools_beta".to_string()
            })
        );
    }

    #[test]
    fn error_taxonomy_provider_status_prefers_invalid_status_code_prefix() {
        assert_eq!(
            provider_error_status("Invalid status code 429 while body says HTTP 503"),
            Some(429)
        );
    }

    #[test]
    fn error_taxonomy_provider_status_marker_scan_is_fallback_only() {
        assert_eq!(
            provider_error_status("HTTP 503 Service Unavailable: upstream overloaded"),
            Some(503)
        );
        assert_eq!(
            provider_error_status("body contains request id 123 and token count 456"),
            None
        );
    }

    #[test]
    fn endpoint_mismatch_detects_inference_time_phrases() {
        for phrase in [
            "method not allowed",
            "unknown route",
            "unknown path",
            "unknown endpoint",
            "no route",
            "no path",
            "route not found",
            "path not found",
            "endpoint not found",
        ] {
            assert!(
                is_endpoint_mismatch_error(&provider_error(phrase)),
                "{phrase}"
            );
        }
    }

    #[test]
    fn endpoint_mismatch_detects_probe_time_phrases() {
        for phrase in [
            "use the responses api",
            "use /v1/responses",
            UNSUPPORTED_API_CODE,
            "not supported on this endpoint",
            "not supported with this endpoint",
            "chat completions endpoint",
            "model is not accessible via the /chat/completions endpoint",
            "responses endpoint",
            "unsupported endpoint",
        ] {
            assert!(is_endpoint_mismatch_error_text(phrase), "{phrase}");
        }
    }

    #[test]
    fn endpoint_mismatch_inference_and_probe_agree() {
        for phrase in [
            "method not allowed",
            "unknown route",
            "unknown path",
            "unknown endpoint",
            "no route",
            "no path",
            "route not found",
            "path not found",
            "endpoint not found",
            "use the responses api",
            "use /v1/responses",
            UNSUPPORTED_API_CODE,
            "not supported on this endpoint",
            "not supported with this endpoint",
            "chat completions endpoint",
            "model is not accessible via the /chat/completions endpoint",
            "responses endpoint",
            "unsupported endpoint",
        ] {
            assert_eq!(
                is_endpoint_mismatch_error(&provider_error(phrase)),
                is_endpoint_mismatch_error_text(phrase),
                "{phrase}"
            );
        }
    }

    #[test]
    fn endpoint_mismatch_uses_shared_unsupported_api_code_const() {
        let body = format!("{{\"error\":{{\"code\":\"{UNSUPPORTED_API_CODE}\"}}}}");
        assert!(is_endpoint_mismatch_error_text(&body));
        assert!(is_endpoint_mismatch_error(&CompletionError::HttpError(
            rig::http_client::Error::InvalidStatusCodeWithMessage(
                reqwest::StatusCode::BAD_REQUEST,
                body,
            ),
        )));
    }
}
