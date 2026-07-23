//! Network-drop auto-retry for inference calls.
//!
//! Wraps a single provider round-trip so a transient network failure
//! (wifi dropped, laptop slept, the link reset mid-stream) auto-retries
//! instead of failing the turn — targeting "closed the laptop on the
//! train" (prompt: implementation note).
//!
//! ## Where this sits
//!
//! [`with_retry`] is invoked from inside
//! [`crate::engine::model::Model::complete_captured`], wrapping the
//! *whole* stream build + drain as one retryable unit. The partial of a
//! failed attempt is discarded (the closure builds a fresh stream each
//! attempt — there is no resume of a half-streamed response), and only
//! the final `Ok`/`Err` propagates out of `complete_captured`. That
//! placement means the persistence in [`crate::engine::agent::turn`]
//! (`record_inference_request` / `record_usage` / the session-log
//! event) runs **once**, on the final outcome — never per attempt — so
//! a retried call yields exactly one logged inference outcome and the
//! wire/user transcript split is preserved.
//!
//! ## Give-up policy
//!
//! Transient failures retry up to [`DEFAULT_MAX_RETRIES`] times by default.
//! The *interval* is capped (exponential + jitter, [`BACKOFF_CAP`]), and
//! the call is always cancellable via the existing per-turn
//! [`CancellationToken`] (ctrl-c → `CancelTurn`). A non-transient error
//! (4xx auth/bad-request, serialization, malformed response) fails fast.
//!
//! ## Active reconnection probe
//!
//! During a backoff wait we run a lightweight connectivity probe (TCP
//! connect to the provider host:port, falling back to a DNS resolve) so
//! a retry fires *promptly* when the network returns rather than waiting
//! out the full capped interval. The backoff governs the probe cadence;
//! a successful probe short-circuits the remaining wait. The probe is
//! abstracted behind [`ConnectivityProbe`] so the loop is testable with
//! a fake (the live TCP/DNS probe is environment-dependent).

use std::time::Duration;

use rig::completion::CompletionError;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::engine::agent::TurnEvent;
use crate::engine::model::InferenceErrorClass;

/// First backoff interval (before jitter). Doubles each repeated
/// failure up to [`BACKOFF_CAP`].
const BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Maximum backoff interval (before jitter). The prompt asks for a
/// ~30–60s cap so the wait never grows unbounded on a long outage; we
/// pick 30s — long enough to stop hammering a dead link, short enough
/// that, absent a probe hit, we still re-check connectivity twice a
/// minute.
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Per-probe timeout. The probe is a liveness check, not the real
/// request — keep it short so a still-dead network fails the probe fast
/// and we fall back to sleeping out the remaining interval.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Default number of retries after the initial failed attempt.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default total attempts for one inference retry unit.
pub const DEFAULT_MAX_ATTEMPTS: u32 = DEFAULT_MAX_RETRIES + 1;

/// What to do with a failed inference attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Network/transient failure with no provider-supplied delay: retry
    /// after the computed exponential-backoff interval (probe may
    /// short-circuit it).
    Retry,
    /// Transient HTTP response (`429`/`503`) — retry, honoring the
    /// provider's `Retry-After` when present. `None` means the header
    /// was absent/unparseable, so fall back to normal backoff.
    RetryAfter(Option<Duration>),
    /// Non-transient failure (4xx auth/bad-request, serialization, URL,
    /// malformed response, or a status we deliberately don't retry).
    /// Surface it immediately.
    FailFast,
}

pub(crate) fn failure_retry_decision_and_rationale(
    class: &InferenceErrorClass,
    provider_status: Option<u16>,
) -> (&'static str, &'static str) {
    match class {
        InferenceErrorClass::TimeoutTtft => ("fail_fast", "time_to_first_token_timeout"),
        InferenceErrorClass::TimeoutIdle => ("fail_fast", "stream_idle_timeout"),
        InferenceErrorClass::Network => (
            "terminal_after_retry_layer",
            "transport_or_provider_failure_after_retry_layer",
        ),
        InferenceErrorClass::MissingToolEntitlement { .. }
        | InferenceErrorClass::ClientSideToolsUnsupported => {
            ("fail_fast", "client_side_capability_block")
        }
        _ if provider_status.is_some_and(|status| status == 429 || status == 503) => (
            "terminal_after_retry_layer",
            "retryable_http_status_terminal",
        ),
        _ if provider_status.is_some_and(|status| (500..=599).contains(&status)) => {
            ("terminal_after_retry_layer", "server_http_status_terminal")
        }
        _ if provider_status.is_some_and(|status| (400..=499).contains(&status)) => {
            ("fail_fast", "non_retryable_http_status")
        }
        InferenceErrorClass::UtilityTimeout
        | InferenceErrorClass::ResponsesToolIdentity
        | InferenceErrorClass::ProviderNotConfigured
        | InferenceErrorClass::ProviderRateLimit
        | InferenceErrorClass::Http(_)
        | InferenceErrorClass::Other(_) => ("fail_fast", "non_retryable_or_unclassified_failure"),
    }
}

pub(crate) fn is_usage_limit_failure(
    class: &InferenceErrorClass,
    provider_status: Option<u16>,
) -> bool {
    provider_status == Some(429)
        || matches!(
            class,
            InferenceErrorClass::Http(429) | InferenceErrorClass::ProviderRateLimit
        )
}

/// Classify a [`CompletionError`] into the retry taxonomy.
///
/// Built on how rig 0.37 + reqwest 0.13 surface errors (verified via
/// `kcl ask rig` and reading `rig-core` / `reqwest` sources):
///
/// | rig error | meaning | decision |
/// |-----------|---------|----------|
/// | `HttpError(InvalidStatusCode(s))` / `InvalidStatusCodeWithMessage(s, _)` | non-2xx HTTP response | `s` is `429`/`503` → `RetryAfter`; other `5xx` → `Retry`; other `4xx` → `FailFast` |
/// | `HttpError(Instance(e))` where `e` downcasts to `reqwest::Error` | transport failure (connect / DNS / timeout / read) | connect/timeout/request/body/decode → `Retry`; status-carrying → fold into the status arm; builder → `FailFast` |
/// | `HttpError(Instance(e))`, non-reqwest inner error | opaque transport box | conservative `Retry` (it is on the transport path) |
/// | `HttpError(Protocol \| StreamEnded \| NoHeaders \| InvalidContentType \| InvalidHeaderValue)` | framing/header faults, not auth | see notes below |
/// | `JsonError` / `UrlError` / `RequestError` / `ResponseError` | serialization / bad URL / request-build / malformed body | `FailFast` |
/// | provider-formatted error string | usually has **no status code exposed** | narrow status parse for clear transient `429`/`503`, otherwise `FailFast` (see note) |
///
/// ### Deliberate, documented edge calls
///
/// - **`StreamEnded`**: rig yields this when the SSE body ends without a
///   terminal event — exactly the mid-stream link-drop case the prompt
///   calls out. Treated as `Retry` (discard the partial, re-issue).
/// - **`Instance` with a non-reqwest inner error**: rig boxes the
///   transport error as `Box<dyn Error>`. If it is a `reqwest::Error` we
///   inspect it precisely; if it downcasts to nothing we recognize, it
///   still arrived on the transport path, so we choose the conservative
///   *retryable* default rather than failing a possibly-recoverable
///   network blip. This is the one class we cannot fully distinguish;
///   the conservative call here is "retry" because the variant is
///   transport-only by construction (rig only produces `Instance` from
///   `req.send()`/`client.execute()`/chunk errors).
/// - **`ProviderError`**: a provider-formatted error *string* with the
///   HTTP status often already consumed by rig. We apply a narrow,
///   status-shaped parse only when the string clearly names a transient
///   status (`429` or `503`) and otherwise keep the
///   conservative **fail-fast** default. This avoids treating generic
///   prose like "rate limited" as retryable while still covering
///   provider bodies that surface as provider-formatted `HTTP 503` strings.
/// - **`Protocol` / `NoHeaders` / `InvalidContentType` /
///   `InvalidHeaderValue`**: malformed framing or our own bad header —
///   not a dropped link and not transient, so `FailFast`.
///
/// `Retry-After` cannot be recovered for status errors: rig's
/// `non_success_status_error` reads the body and **discards the response
/// headers** before building `InvalidStatusCodeWithMessage`, so the
/// header value never reaches us. We therefore parse `Retry-After` only
/// when it is *available*, which in this stack is never for the
/// streaming path — so `RetryAfter(None)` (normal backoff) is what a
/// `429`/`503` actually gets today. The parser ([`parse_retry_after`])
/// is implemented and unit-tested so that the moment a provider variant
/// surfaces the header (e.g. a future Anthropic variant), wiring it is a
/// one-liner with no taxonomy change.
pub fn classify(err: &CompletionError) -> RetryDecision {
    match err {
        CompletionError::HttpError(http_err) => classify_http(http_err),
        // Serialization, bad URL, request-build, malformed response body:
        // re-issuing the identical request would fail identically.
        CompletionError::JsonError(_)
        | CompletionError::UrlError(_)
        | CompletionError::RequestError(_)
        | CompletionError::ResponseError(_) => RetryDecision::FailFast,
        // Provider-formatted error string: only retry when it clearly
        // carries a transient HTTP status; otherwise fail fast.
        err if crate::engine::model::rig_boundary::provider_error_status_for_retry(err)
            .is_some() =>
        {
            classify_status(
                crate::engine::model::rig_boundary::provider_error_status_for_retry(err)
                    .expect("guarded provider status"),
                None,
            )
        }
        _ => RetryDecision::FailFast,
    }
}

fn classify_http(err: &rig::http_client::Error) -> RetryDecision {
    use rig::http_client::Error as H;
    match err {
        H::InvalidStatusCode(status) => classify_status(status.as_u16(), None),
        H::InvalidStatusCodeWithMessage(status, _msg) => classify_status(status.as_u16(), None),
        // rig wraps the underlying transport error (reqwest) here for
        // both the initial round-trip and every mid-stream chunk.
        H::Instance(boxed) => classify_transport(boxed.as_ref()),
        // Stream body ended without a terminal SSE event — the
        // mid-stream link-drop case. Discard the partial, re-issue.
        H::StreamEnded => RetryDecision::Retry,
        // Framing / header / our-own-bad-header faults: not a dropped
        // link, not transient.
        H::Protocol(_) | H::NoHeaders | H::InvalidContentType(_) | H::InvalidHeaderValue(_) => {
            RetryDecision::FailFast
        }
    }
}

/// Classify an HTTP status code. `retry_after` is honored for
/// `429`/`503` when present.
fn classify_status(status: u16, retry_after: Option<Duration>) -> RetryDecision {
    match status {
        // Rate limited / service unavailable: retry, honoring the
        // provider's pacing hint when we have one.
        429 | 503 => RetryDecision::RetryAfter(retry_after),
        // Other server-side faults: transient, retry on backoff.
        500..=599 => RetryDecision::Retry,
        // 4xx (auth, bad request, not found, …) and anything else:
        // re-issuing won't help.
        _ => RetryDecision::FailFast,
    }
}

/// Classify a boxed transport error. We try to downcast to a concrete
/// `reqwest::Error` for a precise verdict; failing that (an inner error
/// type we don't recognize) we fall back to the conservative retryable
/// default, because rig only ever produces `Instance` on the transport
/// path.
fn classify_transport(boxed: &(dyn std::error::Error + 'static)) -> RetryDecision {
    // Walk the error chain looking for a reqwest::Error — rig boxes it
    // directly today, but downcasting through the source chain is robust
    // to an extra wrapper.
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(boxed);
    while let Some(err) = current {
        if let Some(re) = err.downcast_ref::<reqwest::Error>() {
            return classify_reqwest(re);
        }
        current = err.source();
    }
    // Unrecognized transport error: conservative retry (documented).
    RetryDecision::Retry
}

/// Precise classification of a concrete `reqwest::Error`.
fn classify_reqwest(err: &reqwest::Error) -> RetryDecision {
    // A status-carrying reqwest error (from `error_for_status`) folds
    // into the status taxonomy so it gets the same 5xx/429 treatment.
    if let Some(status) = err.status() {
        return classify_status(status.as_u16(), None);
    }
    // Connection refused/reset, no route to host, TLS handshake failure
    // from a dropped link, DNS resolution failure, request timeout, and
    // body/decode read errors from a link drop mid-stream: all transient.
    if err.is_connect() || err.is_timeout() || err.is_request() || err.is_body() || err.is_decode()
    {
        return RetryDecision::Retry;
    }
    // `is_builder` (a malformed request we constructed) and any residual
    // class: re-issuing won't help.
    RetryDecision::FailFast
}

/// Parse an HTTP `Retry-After` header value: either delta-seconds
/// (`"120"`) or an HTTP-date. Returns the delay from now, clamped to be
/// non-negative; `None` for an unparseable value or a date in the past.
///
/// Not currently fed by the streaming path (rig 0.37 discards response
/// headers on status errors — see [`classify`]), but implemented +
/// tested so a future provider variant that surfaces the header (or a
/// rig version that preserves it) wires in with a one-line change to
/// `classify_status`. Deliberately retained, hence the `dead_code`
/// allow — this is a complete, tested code path, not a stub.
#[allow(dead_code)]
pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    // delta-seconds form.
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    // HTTP-date form (RFC 7231 — IMF-fixdate / RFC 850 / asctime). chrono
    // parses RFC 2822, which covers IMF-fixdate (`Sun, 06 Nov 1994
    // 08:49:37 GMT`).
    if let Ok(when) = chrono::DateTime::parse_from_rfc2822(value) {
        let now = chrono::Utc::now();
        let delta = when.with_timezone(&chrono::Utc) - now;
        return delta.to_std().ok();
    }
    None
}

/// Compute the (jittered) backoff for attempt `n` (0-based: the wait
/// *before* the (n+1)-th attempt, i.e. after the n-th failure). Doubles
/// from [`BACKOFF_BASE`], capped at [`BACKOFF_CAP`], then multiplied by a
/// random jitter factor in `[0.5, 1.0]` (decorrelated full-jitter style:
/// jitter only ever *reduces* the wait, so the effective interval stays
/// within the cap and reconnects are never delayed *past* the ceiling).
pub fn backoff_for(attempt: u32, jitter: f64) -> Duration {
    let base_ms = BACKOFF_BASE.as_millis() as u64;
    let cap_ms = BACKOFF_CAP.as_millis() as u64;
    // Saturating doubling: `base * 2^attempt`, capped. `checked_shl`-free
    // via saturating mul so a large `attempt` can't overflow.
    let raw = base_ms.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX));
    let capped = raw.min(cap_ms);
    let jittered = (capped as f64 * jitter).round() as u64;
    Duration::from_millis(jittered)
}

fn wait_for_decision(decision: RetryDecision, failures: u32) -> Option<Duration> {
    match decision {
        RetryDecision::FailFast => None,
        RetryDecision::Retry => Some(backoff_for(failures, jitter_factor())),
        RetryDecision::RetryAfter(Some(d)) => Some(d.min(BACKOFF_CAP)),
        RetryDecision::RetryAfter(None) => Some(backoff_for(failures, jitter_factor())),
    }
}

/// Draw a jitter factor in `[0.5, 1.0]`. Split out so [`backoff_for`]
/// stays pure/testable and the RNG touch is isolated.
fn jitter_factor() -> f64 {
    rand::random_range(0.5..=1.0)
}

/// The provider target a retry loop is reconnecting to, surfaced on every
/// [`TurnEvent::Reconnecting`] so the user-facing status (and the headless
/// `run` log) names the unreachable `provider`/`model` at `url`. Built once
/// by the caller and cloned into each event — the values are stable for the
/// whole loop.
#[derive(Debug, Clone)]
pub struct ReconnectTarget {
    pub provider: String,
    pub model: String,
    pub url: String,
}

/// A connectivity probe: returns `true` when the provider host looks
/// reachable. Abstracted so [`with_retry`] is testable with a fake (the
/// live TCP/DNS probe is environment-dependent and must not run in unit
/// tests).
pub trait ConnectivityProbe: Send + Sync {
    /// Probe once. Implementations must be quick (bounded by their own
    /// short timeout) and must never block the caller longer than the
    /// backoff interval.
    fn probe(&self) -> impl std::future::Future<Output = bool> + Send;
}

/// Live probe: TCP-connect to the provider `host:port`, falling back to
/// a DNS resolve when we only have a host. Parsed once from the provider
/// base URL at construction so the hot path is allocation-free.
pub struct TcpProbe {
    host: String,
    port: u16,
}

impl TcpProbe {
    /// Build a probe target from a provider base URL (e.g.
    /// `https://api.minimax.io/v1`). Returns `None` when the URL has no
    /// host (e.g. a malformed/relative URL) — the caller then skips the
    /// probe and relies on plain backoff.
    pub fn from_base_url(base_url: &str) -> Option<Self> {
        let url = reqwest::Url::parse(base_url).ok()?;
        let host = url.host_str()?.to_string();
        // Default to the scheme's well-known port when the URL omits one.
        let port = url.port_or_known_default().unwrap_or(443);
        Some(Self { host, port })
    }
}

impl ConnectivityProbe for TcpProbe {
    async fn probe(&self) -> bool {
        let addr = format!("{}:{}", self.host, self.port);
        // A successful TCP connect proves the link + DNS + a listening
        // peer. Bounded by PROBE_TIMEOUT so a still-dead network fails
        // fast and we sleep out the rest of the interval.
        match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => true,
            // Connect refused/unreachable: link may be back but the port
            // isn't — still, DNS resolving means the network is up, which
            // is enough to justify an immediate retry.
            Ok(Err(_)) => self.dns_resolves().await,
            // Timed out: treat as still-down.
            Err(_) => false,
        }
    }
}

impl TcpProbe {
    async fn dns_resolves(&self) -> bool {
        let target = format!("{}:{}", self.host, self.port);
        match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::lookup_host(&target)).await {
            Ok(Ok(mut addrs)) => addrs.next().is_some(),
            _ => false,
        }
    }
}

/// Outcome of one wait period.
enum WaitOutcome {
    /// The wait elapsed (or the probe fired) — proceed to retry.
    Proceed,
    /// The user cancelled during the wait — abort the retry loop.
    Cancelled,
}

/// Wait out a backoff interval, racing it against (a) the cancellation
/// token and (b) periodic connectivity probes. A successful probe
/// short-circuits the remaining wait; cancellation interrupts it
/// *immediately* (not after the timer). Returns how the wait ended.
///
/// We probe on a sub-interval cadence so a reconnect mid-wait is caught
/// promptly without busy-looping: probe roughly every
/// `min(interval, 1s)`, sleeping between probes, all under one `select!`
/// against `cancel`.
async fn wait_with_probe<P: ConnectivityProbe>(
    interval: Duration,
    probe: Option<&P>,
    cancel: &CancellationToken,
) -> WaitOutcome {
    // Probe cadence: tight enough to catch a reconnect fast, but never
    // more often than once a second (and never longer than the interval
    // itself for short early backoffs).
    let probe_every = interval.min(Duration::from_secs(1));
    let deadline = tokio::time::Instant::now() + interval;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return WaitOutcome::Proceed;
        }
        let remaining = deadline - now;
        let tick = probe_every.min(remaining);

        tokio::select! {
            biased;
            // Cancellation wins the race and returns immediately, so a
            // ctrl-c during the wait ends the turn without waiting out
            // the timer.
            _ = cancel.cancelled() => return WaitOutcome::Cancelled,
            _ = tokio::time::sleep(tick) => {}
        }

        // After each sub-interval, probe (if we have one). A hit
        // short-circuits the rest of the wait. The probe itself races
        // cancellation so a ctrl-c mid-probe also returns promptly.
        if let Some(p) = probe {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return WaitOutcome::Cancelled,
                reachable = p.probe() => {
                    if reachable {
                        return WaitOutcome::Proceed;
                    }
                }
            }
        }
    }
}

/// Drive `attempt_fn` with network-drop auto-retry.
///
/// `attempt_fn` builds and runs one full inference round-trip (stream
/// build + drain), returning the aggregated result or a
/// [`CompletionError`]. It is called fresh on every attempt — the
/// partial of a failed attempt is dropped, never resumed.
///
/// - Retryable failures (per [`classify`]) trigger a jittered,
///   capped backoff wait that a connectivity `probe` can short-circuit;
///   cancellation interrupts the wait immediately.
/// - Non-transient failures return immediately (`Err`).
/// - There is no max-attempts ceiling for the network case; the user
///   cancels via `cancel`.
///
/// A `TurnEvent::Reconnecting { attempt, provider, model, url }` is
/// emitted before each backoff wait so the TUI shows a distinct,
/// persistent `reconnecting — <provider>/<model> unreachable at <url>
/// (attempt N)` status (never the generic working spinner; no
/// per-attempt toast spam — it's a single live status line) and the
/// headless `run` path logs a recurring attempt-numbered line. `target`
/// names the unreachable provider/model/url for both.
pub async fn with_retry<T, F, Fut, P>(
    agent_name: &str,
    target: &ReconnectTarget,
    event_tx: Option<&mpsc::Sender<TurnEvent>>,
    cancel: &CancellationToken,
    probe: Option<&P>,
    attempt_fn: F,
) -> Result<T, CompletionError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, CompletionError>>,
    P: ConnectivityProbe,
{
    with_retry_inner(
        agent_name,
        target,
        event_tx,
        cancel,
        probe,
        Some(DEFAULT_MAX_ATTEMPTS),
        attempt_fn,
    )
    .await
}

pub async fn with_retry_max<T, F, Fut, P>(
    agent_name: &str,
    target: &ReconnectTarget,
    event_tx: Option<&mpsc::Sender<TurnEvent>>,
    cancel: &CancellationToken,
    probe: Option<&P>,
    max_attempts: u32,
    attempt_fn: F,
) -> Result<T, CompletionError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, CompletionError>>,
    P: ConnectivityProbe,
{
    with_retry_inner(
        agent_name,
        target,
        event_tx,
        cancel,
        probe,
        Some(max_attempts.max(1)),
        attempt_fn,
    )
    .await
}

async fn with_retry_inner<T, F, Fut, P>(
    agent_name: &str,
    target: &ReconnectTarget,
    event_tx: Option<&mpsc::Sender<TurnEvent>>,
    cancel: &CancellationToken,
    probe: Option<&P>,
    max_attempts: Option<u32>,
    mut attempt_fn: F,
) -> Result<T, CompletionError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, CompletionError>>,
    P: ConnectivityProbe,
{
    // 0-based count of failures so far (drives the backoff exponent and
    // the user-facing 1-based attempt number).
    let mut failures: u32 = 0;
    loop {
        match attempt_fn().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if max_attempts.is_some_and(|max| failures.saturating_add(1) >= max) {
                    return Err(err);
                }
                let decision = classify(&err);
                let Some(wait) = wait_for_decision(decision, failures) else {
                    return Err(err);
                };

                failures = failures.saturating_add(1);
                // Recurring, attempt-numbered log line so a headless `run`
                // (no TUI) is never silently hung on an unreachable server —
                // names provider/model/url + the attempt number, matching the
                // interactive status. `warn` so it surfaces on stderr at the
                // default log level.
                tracing::warn!(
                    attempt = failures,
                    provider = %target.provider,
                    model = %target.model,
                    url = %target.url,
                    wait_ms = wait.as_millis() as u64,
                    error = %err,
                    "inference unreachable — {}/{} at {} (attempt {}); retrying",
                    target.provider,
                    target.model,
                    target.url,
                    failures,
                );

                // Surface the reconnecting status (1-based attempt number
                // = the retry we're about to make), naming the unreachable
                // target so the TUI status reads as a distinct reconnect line.
                if let Some(event_tx) = event_tx {
                    let _ = event_tx
                        .send(TurnEvent::Reconnecting {
                            agent: agent_name.to_string(),
                            attempt: failures,
                            provider: target.provider.clone(),
                            model: target.model.clone(),
                            url: target.url.clone(),
                        })
                        .await;
                }

                match wait_with_probe(wait, probe, cancel).await {
                    WaitOutcome::Proceed => {}
                    WaitOutcome::Cancelled => {
                        // The turn was cancelled during the wait. Return
                        // the last transport error; the model layer maps a
                        // post-cancel state to its `InferenceCancelled`
                        // sentinel, and either way the turn unwinds.
                        return Err(err);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fixed reconnect target for the loop tests.
    fn test_target() -> ReconnectTarget {
        ReconnectTarget {
            provider: "openai-compatible".to_string(),
            model: "glm-4.6".to_string(),
            url: "http://localhost:1234/v1".to_string(),
        }
    }

    // --- taxonomy ---------------------------------------------------

    fn http_status(code: u16) -> CompletionError {
        CompletionError::HttpError(rig::http_client::Error::InvalidStatusCode(
            reqwest::StatusCode::from_u16(code).unwrap(),
        ))
    }

    fn http_status_msg(code: u16) -> CompletionError {
        CompletionError::HttpError(rig::http_client::Error::InvalidStatusCodeWithMessage(
            reqwest::StatusCode::from_u16(code).unwrap(),
            "boom".into(),
        ))
    }

    #[test]
    fn failure_retry_decision_rationale_covers_representative_arms() {
        assert_eq!(
            failure_retry_decision_and_rationale(&InferenceErrorClass::TimeoutTtft, None),
            ("fail_fast", "time_to_first_token_timeout")
        );
        assert_eq!(
            failure_retry_decision_and_rationale(&InferenceErrorClass::Network, None),
            (
                "terminal_after_retry_layer",
                "transport_or_provider_failure_after_retry_layer"
            )
        );
        assert_eq!(
            failure_retry_decision_and_rationale(&InferenceErrorClass::Http(429), Some(429)),
            (
                "terminal_after_retry_layer",
                "retryable_http_status_terminal"
            )
        );
        assert_eq!(
            failure_retry_decision_and_rationale(&InferenceErrorClass::Http(503), Some(503)),
            (
                "terminal_after_retry_layer",
                "retryable_http_status_terminal"
            )
        );
        assert_eq!(
            failure_retry_decision_and_rationale(&InferenceErrorClass::Http(502), Some(502)),
            ("terminal_after_retry_layer", "server_http_status_terminal")
        );
        assert_eq!(
            failure_retry_decision_and_rationale(&InferenceErrorClass::Http(400), Some(400)),
            ("fail_fast", "non_retryable_http_status")
        );
        assert_eq!(
            failure_retry_decision_and_rationale(&InferenceErrorClass::Other("weird".into()), None),
            ("fail_fast", "non_retryable_or_unclassified_failure")
        );
    }

    #[test]
    fn status_taxonomy() {
        // 5xx → retry.
        assert_eq!(classify(&http_status(500)), RetryDecision::Retry);
        assert_eq!(classify(&http_status_msg(502)), RetryDecision::Retry);
        // 429 / 503 → retry-after (None without a header).
        assert_eq!(classify(&http_status(429)), RetryDecision::RetryAfter(None));
        assert_eq!(
            classify(&http_status_msg(503)),
            RetryDecision::RetryAfter(None)
        );
        // 4xx auth/bad-request → fail fast.
        assert_eq!(classify(&http_status(401)), RetryDecision::FailFast);
        assert_eq!(classify(&http_status(400)), RetryDecision::FailFast);
        assert_eq!(classify(&http_status_msg(404)), RetryDecision::FailFast);
    }

    #[test]
    fn classify_status_code_helper() {
        assert_eq!(
            classify_status(503, Some(Duration::from_secs(7))),
            RetryDecision::RetryAfter(Some(Duration::from_secs(7)))
        );
        assert_eq!(classify_status(500, None), RetryDecision::Retry);
        assert_eq!(classify_status(418, None), RetryDecision::FailFast);
    }

    #[test]
    fn stream_ended_is_retryable() {
        // Mid-stream link drop: SSE body ends without a terminal event.
        let err = CompletionError::HttpError(rig::http_client::Error::StreamEnded);
        assert_eq!(classify(&err), RetryDecision::Retry);
    }

    #[test]
    fn framing_faults_fail_fast() {
        let err = CompletionError::HttpError(rig::http_client::Error::NoHeaders);
        assert_eq!(classify(&err), RetryDecision::FailFast);
    }

    #[test]
    fn non_http_errors_fail_fast() {
        assert_eq!(
            classify(&CompletionError::ResponseError("bad".into())),
            RetryDecision::FailFast
        );
        assert_eq!(
            classify(&CompletionError::ProviderError("rate limited".into())),
            RetryDecision::FailFast
        );
        let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        assert_eq!(
            classify(&CompletionError::JsonError(json_err)),
            RetryDecision::FailFast
        );
    }

    #[test]
    fn provider_error_strings_retry_only_clear_transients() {
        assert_eq!(
            classify(&CompletionError::ProviderError(
                "HTTP 503 Service Unavailable: upstream overloaded".into()
            )),
            RetryDecision::RetryAfter(None)
        );
        assert_eq!(
            classify(&CompletionError::ProviderError(
                r#"{"error":{"status":503,"message":"server unavailable"}}"#.into()
            )),
            RetryDecision::RetryAfter(None)
        );
        assert_eq!(
            classify(&CompletionError::ProviderError(
                "401 Unauthorized: invalid API key".into()
            )),
            RetryDecision::FailFast
        );
        assert_eq!(
            classify(&CompletionError::ProviderError(
                r#"{"error":{"status":500,"message":"server error"}}"#.into()
            )),
            RetryDecision::FailFast
        );
    }

    #[tokio::test]
    async fn unrecognized_transport_box_is_conservatively_retried() {
        // An inner error that is NOT a reqwest::Error but arrives on the
        // transport path: conservative retry (documented).
        #[derive(Debug)]
        struct Weird;
        impl std::fmt::Display for Weird {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "weird transport error")
            }
        }
        impl std::error::Error for Weird {}
        let err = CompletionError::HttpError(rig::http_client::Error::Instance(Box::new(Weird)));
        assert_eq!(classify(&err), RetryDecision::Retry);
    }

    // --- Retry-After parsing ---------------------------------------

    #[tokio::test]
    async fn retry_after_delta_seconds() {
        assert_eq!(parse_retry_after("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after("  0 "), Some(Duration::from_secs(0)));
    }

    #[tokio::test]
    async fn retry_after_http_date() {
        // A date far in the future parses to a positive delay.
        let future = (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc2822();
        let parsed = parse_retry_after(&future).expect("future date parses");
        // Allow slack for the seconds that elapse during the test.
        assert!(parsed <= Duration::from_secs(301) && parsed >= Duration::from_secs(290));
    }

    #[tokio::test]
    async fn retry_after_past_date_is_none() {
        let past = (chrono::Utc::now() - chrono::Duration::seconds(300)).to_rfc2822();
        // A past date yields a negative delta → no usable delay.
        assert_eq!(parse_retry_after(&past), None);
    }

    #[tokio::test]
    async fn retry_after_garbage_is_none() {
        assert_eq!(parse_retry_after("not-a-date"), None);
    }

    // --- backoff sequence ------------------------------------------

    #[tokio::test]
    async fn backoff_is_exponential_and_capped() {
        // With jitter = 1.0 (no reduction) we see the raw exponential
        // ladder, capped at BACKOFF_CAP.
        assert_eq!(backoff_for(0, 1.0), Duration::from_millis(500));
        assert_eq!(backoff_for(1, 1.0), Duration::from_millis(1000));
        assert_eq!(backoff_for(2, 1.0), Duration::from_millis(2000));
        assert_eq!(backoff_for(3, 1.0), Duration::from_millis(4000));
        // Eventually pinned at the cap and never beyond it.
        assert_eq!(backoff_for(20, 1.0), BACKOFF_CAP);
        assert_eq!(backoff_for(u32::MAX, 1.0), BACKOFF_CAP);
    }

    #[tokio::test]
    async fn backoff_jitter_stays_within_bounds() {
        // Jitter only ever reduces the wait (full-jitter lower half), so
        // the effective interval is in (0.5 * raw, raw] and never exceeds
        // the cap.
        for attempt in 0..25u32 {
            for _ in 0..50 {
                let j = jitter_factor();
                assert!((0.5..=1.0).contains(&j));
                let d = backoff_for(attempt, j);
                let full = backoff_for(attempt, 1.0);
                assert!(d <= full, "jitter never exceeds the uncapped interval");
                assert!(d <= BACKOFF_CAP, "jitter never exceeds the cap");
            }
        }
    }

    // --- wait/cancel/probe -----------------------------------------

    /// A fake probe with a controllable verdict + call counter.
    struct FakeProbe {
        reachable: bool,
        calls: Arc<AtomicU32>,
    }
    impl ConnectivityProbe for FakeProbe {
        async fn probe(&self) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.reachable
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_during_wait_returns_promptly() {
        // A pre-cancelled token must end the wait immediately, not after
        // the (long) interval elapses.
        let cancel = CancellationToken::new();
        cancel.cancel();
        let probe = FakeProbe {
            reachable: false,
            calls: Arc::new(AtomicU32::new(0)),
        };
        let outcome = wait_with_probe(Duration::from_secs(30), Some(&probe), &cancel).await;
        assert!(matches!(outcome, WaitOutcome::Cancelled));
        // No real time should have to pass — start_paused means the test
        // returns without advancing the clock.
        assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn successful_probe_short_circuits_wait() {
        let cancel = CancellationToken::new();
        let probe = FakeProbe {
            reachable: true,
            calls: Arc::new(AtomicU32::new(0)),
        };
        // 30s interval, but the probe fires after the first 1s sub-tick.
        let outcome = wait_with_probe(Duration::from_secs(30), Some(&probe), &cancel).await;
        assert!(matches!(outcome, WaitOutcome::Proceed));
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_elapses_without_probe() {
        let cancel = CancellationToken::new();
        let outcome = wait_with_probe::<FakeProbe>(Duration::from_millis(500), None, &cancel).await;
        assert!(matches!(outcome, WaitOutcome::Proceed));
    }

    // --- the retry loop: exactly-one-outcome semantics -------------

    #[tokio::test(start_paused = true)]
    async fn fail_then_succeed_runs_attempt_until_success() {
        // The closure fails twice (transient) then succeeds; with_retry
        // must return the success value, having invoked the closure
        // exactly 3 times — the caller persists once on this single Ok.
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
        let cancel = CancellationToken::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = calls.clone();
        let probe = FakeProbe {
            reachable: true,
            calls: Arc::new(AtomicU32::new(0)),
        };

        let target = test_target();
        let result = with_retry(
            "builder",
            &target,
            Some(&tx),
            &cancel,
            Some(&probe),
            move || {
                let n = calls_c.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(CompletionError::HttpError(
                            rig::http_client::Error::StreamEnded,
                        ))
                    } else {
                        Ok::<_, CompletionError>(42u32)
                    }
                }
            },
        )
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // Exactly two Reconnecting events (before each of the two retries),
        // 1-based attempt numbers 1 and 2 — no spam, one per retry — each
        // carrying the unreachable target so the status can name it.
        let mut attempts = vec![];
        while let Ok(ev) = rx.try_recv() {
            if let TurnEvent::Reconnecting {
                attempt,
                provider,
                model,
                url,
                ..
            } = ev
            {
                assert_eq!(provider, "openai-compatible");
                assert_eq!(model, "glm-4.6");
                assert_eq!(url, "http://localhost:1234/v1");
                attempts.push(attempt);
            }
        }
        assert_eq!(attempts, vec![1, 2]);
    }

    #[tokio::test(start_paused = true)]
    async fn fail_fast_returns_immediately_without_retry() {
        let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
        let cancel = CancellationToken::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = calls.clone();

        let target = test_target();
        let result: Result<u32, _> = with_retry(
            "builder",
            &target,
            Some(&tx),
            &cancel,
            None::<&FakeProbe>,
            move || {
                calls_c.fetch_add(1, Ordering::SeqCst);
                async { Err(CompletionError::ResponseError("bad request".into())) }
            },
        )
        .await;

        assert!(result.is_err());
        // Called exactly once — no retry on a non-transient error.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn default_retry_loop_stops_after_three_retries() {
        let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
        let cancel = CancellationToken::new();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = calls.clone();
        let probe = FakeProbe {
            reachable: true,
            calls: Arc::new(AtomicU32::new(0)),
        };

        let target = test_target();
        let result: Result<u32, _> = with_retry(
            "builder",
            &target,
            Some(&tx),
            &cancel,
            Some(&probe),
            move || {
                calls_c.fetch_add(1, Ordering::SeqCst);
                async { Err(http_status(500)) }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), DEFAULT_MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn retry_after_wait_is_capped_at_thirty_seconds() {
        assert_eq!(
            wait_for_decision(RetryDecision::RetryAfter(Some(Duration::from_secs(120))), 0,),
            Some(BACKOFF_CAP)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_during_retry_wait_aborts_the_loop() {
        // The closure always fails transiently; a pre-cancelled token
        // must abort the loop on the first wait rather than spinning
        // forever.
        let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = calls.clone();

        let target = test_target();
        let result: Result<u32, _> = with_retry(
            "builder",
            &target,
            Some(&tx),
            &cancel,
            None::<&FakeProbe>,
            move || {
                calls_c.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(CompletionError::HttpError(
                        rig::http_client::Error::StreamEnded,
                    ))
                }
            },
        )
        .await;

        assert!(result.is_err());
        // One attempt, then the (pre-cancelled) wait aborts the loop.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
