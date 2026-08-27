//! ComfyUI image-generation dispatch adapter (AC4 / AC6-comfyui).
//!
//! Wires the pure ComfyUI request/response logic in
//! [`crate::image_generation_comfyui`] behind the sealed
//! [`ImageGenerationAdapter`] dispatch trait through a single transport seam.
//! The multi-step path is:
//!
//! * **handoff** — `POST /prompt` with the bound workflow graph and a unique
//!   `client_id`. A 2xx carrying a `prompt_id` is an accepted submission; a 2xx
//!   without a parseable `prompt_id` is `submission_unknown` (the job may be
//!   running but is unidentifiable — never guessed, never resubmitted, never
//!   mis-reported as a definitive rejection);
//! * **reconcile** — `GET /history/{prompt_id}` (bounded by
//!   [`MAX_HISTORY_RESPONSE_BYTES`]) then, for a completed prompt, a bounded
//!   `GET /view` (bounded by [`MAX_VIEW_DOWNLOAD_BYTES`]) per declared output
//!   artifact. Both bounds are enforced **while reading** by the shared
//!   [`VettedHttpClient`];
//! * **cancel** — maps the discovered [`ComfyCancellationCapability`] onto an
//!   exact cancel call and folds its result into the adapter cancel vocabulary.
//!
//! Every byte leaves through the shared pinned/vetted transport, which vets the
//! full DNS answer set to the endpoint's declared location class before sending.

use std::sync::Arc;

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};

use cockpit_config::config::image_generation::{ImageLocationClass, WorkflowOutput};

use crate::image_generation::http_transport::{
    ProviderTransportConfigError, VettedHttpClient, validate_http_or_https_origin,
};
use crate::image_generation::transport::{
    ProviderTransportError, ProviderTransportOutcome, SubmissionDisposition,
};
use crate::image_generation_comfyui::{
    ComfyCancellationCapability, ComfyPromptPayload, ComfyPromptResponse, ComfyViewRequest,
    parse_history_response,
};
use crate::image_generation_job::{
    ImageGenerationAdapter, ImageGenerationCancelRequest, ImageGenerationCancelResult,
    ImageGenerationHandoffRequest, ImageGenerationHandoffResult, ImageGenerationReconcileRequest,
    ImageGenerationReconcileResult, image_generation_adapter_sealed,
};
use crate::image_generation_runtime::{DnsResolver, declared_class};

// ---------------------------------------------------------------------------
// Named byte bounds (AC6-comfyui). Each is enforced WHILE READING by the shared
// VettedHttpClient because it is threaded into the request's `body_limit`.
// ---------------------------------------------------------------------------

/// Max bytes for a `POST /prompt` response (a small JSON `{ "prompt_id": ... }`).
pub const MAX_PROMPT_RESPONSE_BYTES: usize = 64 * 1024;
/// Max bytes for a `POST /upload/image` response (a small JSON ack).
pub const MAX_UPLOAD_RESPONSE_BYTES: usize = 64 * 1024;
/// Max bytes for a `GET /history/{prompt_id}` response.
pub const MAX_HISTORY_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Max bytes for a single `GET /view` artifact download.
pub const MAX_VIEW_DOWNLOAD_BYTES: usize = 32 * 1024 * 1024;
/// Max bytes for a cancel/interrupt response.
pub const MAX_CANCEL_RESPONSE_BYTES: usize = 64 * 1024;

const EVIDENCE_DETAIL_MAX_CHARS: usize = 512;

pub(crate) mod comfyui_adapter_sealed {
    pub trait Sealed {}
}

/// HTTP method for a ComfyUI request. ComfyUI's routes are GET (history/view)
/// or POST (prompt/upload/cancel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComfyMethod {
    Get,
    Post,
}

/// One bounded ComfyUI HTTP request. `path` is a relative path already built
/// from the fixed route table with any `{param}` substituted by a validated
/// opaque identifier; `body_limit` is one of the named bounds above and is
/// enforced while the response is read.
#[derive(Debug, Clone)]
pub struct ComfyHttpRequest {
    pub method: ComfyMethod,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<&'static str>,
    pub body_limit: usize,
}

/// Transport seam for ComfyUI. Production wires this to
/// [`ComfyuiHttpTransport`]; tests wire a scripted transport. The seam is the
/// only place a request byte leaves the process.
#[async_trait::async_trait]
pub trait ComfyuiTransport: comfyui_adapter_sealed::Sealed + Send + Sync {
    async fn call(
        &self,
        request: ComfyHttpRequest,
    ) -> Result<ProviderTransportOutcome, ProviderTransportError>;
}

/// A production pinned HTTP(S) transport bound to one ComfyUI origin.
///
/// Constructible only through [`ComfyuiHttpTransport::vetted`]. The peer address
/// class is vetted against the endpoint's declared location, so a loopback/LAN
/// ComfyUI server reached over plain `http` is dialed only when its resolved
/// address is in the declared class. Any caller-supplied header credential is
/// held sensitive and redacted in `Debug`.
pub struct ComfyuiHttpTransport {
    origin: Url,
    path_prefix: String,
    headers: HeaderMap,
    dns: Arc<dyn DnsResolver>,
    required_location: crate::image_generation_runtime::AddressClass,
}

impl std::fmt::Debug for ComfyuiHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ComfyuiHttpTransport")
            .field("origin", &self.origin.as_str())
            .field("path_prefix", &self.path_prefix)
            .field("headers", &"<redacted>")
            .field("required_location", &self.required_location)
            .finish()
    }
}

impl ComfyuiHttpTransport {
    /// The single vetted constructor. Validates the origin, normalizes the
    /// optional path prefix, binds any caller-supplied headers (marking them
    /// sensitive), and fixes the required peer class from the declared location.
    pub fn vetted(
        origin: &str,
        path_prefix: Option<&str>,
        location: ImageLocationClass,
        dns: Arc<dyn DnsResolver>,
        headers: Vec<(String, String)>,
    ) -> Result<Self, ProviderTransportConfigError> {
        let origin = validate_http_or_https_origin(origin)?;
        // A path prefix must be a strict relative path that cannot change the
        // URL authority: empty, or `/`-rooted with no scheme, authority, or
        // protocol-relative (`//`) component.
        let path_prefix = {
            let raw = path_prefix.unwrap_or("").trim_end_matches('/');
            if raw.is_empty() {
                String::new()
            } else if !raw.starts_with('/')
                || raw.contains("//")
                || raw.contains("://")
                || raw.contains('@')
                || raw.contains(|c: char| c.is_whitespace())
            {
                return Err(ProviderTransportConfigError::ForbiddenOriginComponent);
            } else {
                raw.to_string()
            }
        };
        let mut header_map = HeaderMap::new();
        for (name, value) in headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
            let mut header_value = HeaderValue::from_str(&value)
                .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
            // A configured endpoint header may be a credential; keep it off
            // reqwest's own logs.
            header_value.set_sensitive(true);
            header_map.insert(header_name, header_value);
        }
        Ok(Self {
            origin,
            path_prefix,
            headers: header_map,
            dns,
            required_location: declared_class(location),
        })
    }
}

impl comfyui_adapter_sealed::Sealed for ComfyuiHttpTransport {}

#[async_trait::async_trait]
impl ComfyuiTransport for ComfyuiHttpTransport {
    async fn call(
        &self,
        request: ComfyHttpRequest,
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        let relative = format!("{}{}", self.path_prefix, request.path);
        let mut url = self
            .origin
            .join(relative.trim_start_matches('/'))
            .map_err(|_| ProviderTransportError::Connect)?;
        // Defense in depth: neither the (validated) path prefix nor a substituted
        // path identifier may change the URL authority. A join that alters the
        // scheme/host/port would send the configured (possibly sensitive) headers
        // to a different origin, so it fails closed before any byte is sent.
        if url.origin() != self.origin.origin() {
            return Err(ProviderTransportError::Connect);
        }
        if !request.query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in &request.query {
                pairs.append_pair(key, value);
            }
            drop(pairs);
        }
        let mut headers = self.headers.clone();
        if let Some(content_type) = request.content_type {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        let method = match request.method {
            ComfyMethod::Get => Method::GET,
            ComfyMethod::Post => Method::POST,
        };
        VettedHttpClient::new(self.dns.clone(), self.required_location)
            .execute(method, &url, headers, request.body, request.body_limit)
            .await
    }
}

// ---------------------------------------------------------------------------
// Attempt / reconcile / cancel plan inputs and the plan-source seam.
// ---------------------------------------------------------------------------

/// The immutable per-attempt handoff inputs (bound workflow + unique client id).
#[derive(Debug, Clone)]
pub struct ComfyuiImagesAttemptInput {
    /// The bound workflow graph JSON (only declared values mutated).
    pub prompt_graph: serde_json::Value,
    /// The unique Cockpit-owned `client_id` for this attempt.
    pub client_id: String,
}

/// Inputs to reconcile a submitted prompt.
#[derive(Debug, Clone)]
pub struct ComfyuiReconcileInput {
    pub prompt_id: String,
    pub declared_outputs: Vec<WorkflowOutput>,
}

/// Inputs to cancel a submitted prompt via an exact capability.
#[derive(Debug, Clone)]
pub struct ComfyuiCancelInput {
    pub capability: ComfyCancellationCapability,
    pub prompt_id: Option<String>,
    pub job_id: Option<String>,
}

/// Resolves the immutable per-phase plan from a dispatch request.
#[async_trait::async_trait]
pub trait ComfyuiImagesPlanSource: comfyui_adapter_sealed::Sealed + Send + Sync {
    async fn resolve_handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ComfyuiImagesPlanResolution;
    async fn resolve_reconcile(
        &self,
        request: &ImageGenerationReconcileRequest,
    ) -> Option<ComfyuiReconcileInput>;
    async fn resolve_cancel(
        &self,
        request: &ImageGenerationCancelRequest,
    ) -> Option<ComfyuiCancelInput>;
}

/// Outcome of resolving the per-attempt handoff plan.
#[derive(Debug, Clone)]
pub enum ComfyuiImagesPlanResolution {
    Resolved(Box<ComfyuiImagesAttemptInput>),
    Unresolvable { safe_reason: String },
}

/// The ComfyUI Images dispatch adapter.
pub struct ComfyuiImagesAdapter {
    transport: Arc<dyn ComfyuiTransport>,
    plan_source: Arc<dyn ComfyuiImagesPlanSource>,
}

impl ComfyuiImagesAdapter {
    pub fn new(
        transport: Arc<dyn ComfyuiTransport>,
        plan_source: Arc<dyn ComfyuiImagesPlanSource>,
    ) -> Self {
        Self {
            transport,
            plan_source,
        }
    }
}

impl image_generation_adapter_sealed::Sealed for ComfyuiImagesAdapter {}

#[async_trait::async_trait]
impl ImageGenerationAdapter for ComfyuiImagesAdapter {
    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        let input = match self.plan_source.resolve_handoff(request).await {
            ComfyuiImagesPlanResolution::Resolved(input) => *input,
            ComfyuiImagesPlanResolution::Unresolvable { safe_reason } => {
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: comfy_evidence(b"plan_unresolvable", &safe_reason),
                };
            }
        };
        let payload = ComfyPromptPayload {
            prompt: input.prompt_graph,
            client_id: input.client_id,
        };
        let body = match serde_json::to_vec(&payload) {
            Ok(body) => body,
            Err(_) => {
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: comfy_evidence(b"request_serialize", "serialize failed"),
                };
            }
        };
        let http = ComfyHttpRequest {
            method: ComfyMethod::Post,
            path: "/prompt".to_string(),
            query: Vec::new(),
            body: Some(body),
            content_type: Some("application/json"),
            body_limit: MAX_PROMPT_RESPONSE_BYTES,
        };
        match self.transport.call(http).await {
            Ok(outcome) => {
                match serde_json::from_slice::<ComfyPromptResponse>(&outcome.body) {
                    Ok(parsed) if !parsed.prompt_id.is_empty() => {
                        ImageGenerationHandoffResult::Accepted {
                            evidence: comfy_evidence(b"accepted", "prompt accepted"),
                        }
                    }
                    // A 2xx with no usable prompt_id: the server may be running
                    // the job but it is unidentifiable. Never guess a prompt id
                    // or resubmit — reconcile decides.
                    _ => ImageGenerationHandoffResult::SubmissionUnknown {
                        evidence: comfy_evidence(b"accepted_no_prompt_id", "unidentifiable job"),
                    },
                }
            }
            Err(error) => match error.submission_disposition() {
                SubmissionDisposition::DefinitivelyRejected => {
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: comfy_evidence(
                            b"definitive_nonacceptance",
                            comfy_error_detail(&error),
                        ),
                    }
                }
                SubmissionDisposition::SubmissionUnknown => {
                    ImageGenerationHandoffResult::SubmissionUnknown {
                        evidence: comfy_evidence(b"post_handoff_ambiguous", "handoff accepted"),
                    }
                }
            },
        }
    }

    async fn reconcile(
        &self,
        request: &ImageGenerationReconcileRequest,
    ) -> ImageGenerationReconcileResult {
        let Some(input) = self.plan_source.resolve_reconcile(request).await else {
            return ImageGenerationReconcileResult::OutcomeUnknown {
                evidence: comfy_evidence(b"reconcile_no_prompt", "no prompt binding"),
            };
        };
        let history = ComfyHttpRequest {
            method: ComfyMethod::Get,
            path: format!("/history/{}", input.prompt_id),
            query: Vec::new(),
            body: None,
            content_type: None,
            body_limit: MAX_HISTORY_RESPONSE_BYTES,
        };
        let outcome = match self.transport.call(history).await {
            Ok(outcome) => outcome,
            // A history read failure is never authoritative: the job may still
            // be running/paid. Reconcile again later.
            Err(_error) => {
                return ImageGenerationReconcileResult::OutcomeUnknown {
                    evidence: comfy_evidence(b"history_unavailable", "history read failed"),
                };
            }
        };
        let value: serde_json::Value = match serde_json::from_slice(&outcome.body) {
            Ok(value) => value,
            Err(_) => {
                return ImageGenerationReconcileResult::OutcomeUnknown {
                    evidence: comfy_evidence(b"history_unparseable", "history not json"),
                };
            }
        };
        let parsed = match parse_history_response(&value, &input.prompt_id, &input.declared_outputs)
        {
            Ok(parsed) => parsed,
            Err(_) => {
                return ImageGenerationReconcileResult::OutcomeUnknown {
                    evidence: comfy_evidence(b"history_invalid", "history shape invalid"),
                };
            }
        };
        if !parsed.completed {
            return ImageGenerationReconcileResult::OutcomeUnknown {
                evidence: comfy_evidence(b"history_pending", "prompt not completed"),
            };
        }
        if parsed.outputs.is_empty() {
            // A completed prompt that produced no declared output artifact is an
            // authoritative failure (nothing to retrieve).
            return ImageGenerationReconcileResult::AuthoritativeFailure {
                evidence: comfy_evidence(b"completed_no_outputs", "no declared outputs"),
            };
        }
        // Download each declared artifact through the bounded /view path. A
        // download failure keeps the outcome unknown (the paid job succeeded;
        // retry the retrieval) rather than inventing a failure.
        let mut downloaded = 0usize;
        for artifact in &parsed.outputs {
            let view = match ComfyViewRequest::from_artifact(artifact) {
                Ok(view) => view,
                Err(_) => {
                    return ImageGenerationReconcileResult::OutcomeUnknown {
                        evidence: comfy_evidence(b"view_identifier_invalid", "bad artifact id"),
                    };
                }
            };
            let request = ComfyHttpRequest {
                method: ComfyMethod::Get,
                path: "/view".to_string(),
                query: view
                    .to_query_params()
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                body: None,
                content_type: None,
                body_limit: MAX_VIEW_DOWNLOAD_BYTES,
            };
            match self.transport.call(request).await {
                Ok(_bytes) => downloaded += 1,
                Err(_error) => {
                    return ImageGenerationReconcileResult::OutcomeUnknown {
                        evidence: comfy_evidence(
                            b"view_download_failed",
                            "artifact download failed",
                        ),
                    };
                }
            }
        }
        ImageGenerationReconcileResult::AuthoritativeAccepted {
            evidence: comfy_evidence(b"reconciled_accepted", &format!("artifacts={downloaded}")),
        }
    }

    async fn cancel(&self, request: &ImageGenerationCancelRequest) -> ImageGenerationCancelResult {
        let Some(input) = self.plan_source.resolve_cancel(request).await else {
            return ImageGenerationCancelResult::OutcomeUnknown {
                evidence: comfy_evidence(b"cancel_no_binding", "no cancel binding"),
            };
        };
        let http = match cancel_request(&input) {
            Some(http) => http,
            // No safe provider cancellation is available: record the request as
            // unknown (the caller quarantines any later result).
            None => {
                return ImageGenerationCancelResult::OutcomeUnknown {
                    evidence: comfy_evidence(b"cancel_unsupported", input.capability.as_str()),
                };
            }
        };
        let job_scoped = input.capability == ComfyCancellationCapability::JobScopedCancel;
        match self.transport.call(http).await {
            Ok(outcome) => {
                if job_scoped {
                    // The job-scoped route returns an idempotent
                    // `{ "cancelled": bool }`.
                    match serde_json::from_slice::<CancelAck>(&outcome.body) {
                        Ok(ack) if ack.cancelled => ImageGenerationCancelResult::Cancelled {
                            evidence: comfy_evidence(b"cancelled", "provider confirmed"),
                        },
                        Ok(_) => ImageGenerationCancelResult::TooLateOrAccepted {
                            evidence: comfy_evidence(b"cancel_too_late", "already accepted"),
                        },
                        Err(_) => ImageGenerationCancelResult::OutcomeUnknown {
                            evidence: comfy_evidence(b"cancel_unparseable", "ack not json"),
                        },
                    }
                } else {
                    // Queued-delete / interrupt: a 2xx is an accepted cancel.
                    ImageGenerationCancelResult::Cancelled {
                        evidence: comfy_evidence(b"cancelled", "queued delete/interrupt accepted"),
                    }
                }
            }
            // A cancel transport failure never claims a cancellation nor an
            // acceptance: reconcile decides.
            Err(_error) => ImageGenerationCancelResult::OutcomeUnknown {
                evidence: comfy_evidence(b"cancel_ambiguous", "cancel call failed"),
            },
        }
    }
}

/// The idempotent `{ "cancelled": bool }` ack from the job-scoped cancel route.
#[derive(Debug, Clone, serde::Deserialize)]
struct CancelAck {
    cancelled: bool,
}

/// Build the exact cancel request for a capability, or `None` for the
/// unsupported capability.
fn cancel_request(input: &ComfyuiCancelInput) -> Option<ComfyHttpRequest> {
    match input.capability {
        ComfyCancellationCapability::JobScopedCancel => {
            let job_id = input.job_id.as_deref()?;
            Some(ComfyHttpRequest {
                method: ComfyMethod::Post,
                path: format!("/api/jobs/{job_id}/cancel"),
                query: Vec::new(),
                body: Some(b"{}".to_vec()),
                content_type: Some("application/json"),
                body_limit: MAX_CANCEL_RESPONSE_BYTES,
            })
        }
        ComfyCancellationCapability::QueuedPromptDelete => {
            let prompt_id = input.prompt_id.as_deref()?;
            let body = serde_json::to_vec(&serde_json::json!({ "delete": [prompt_id] })).ok()?;
            Some(ComfyHttpRequest {
                method: ComfyMethod::Post,
                path: "/queue".to_string(),
                query: Vec::new(),
                body: Some(body),
                content_type: Some("application/json"),
                body_limit: MAX_CANCEL_RESPONSE_BYTES,
            })
        }
        ComfyCancellationCapability::ExclusiveServerInterrupt => Some(ComfyHttpRequest {
            method: ComfyMethod::Post,
            path: "/interrupt".to_string(),
            query: Vec::new(),
            body: Some(b"{}".to_vec()),
            content_type: Some("application/json"),
            body_limit: MAX_CANCEL_RESPONSE_BYTES,
        }),
        ComfyCancellationCapability::Unsupported => None,
    }
}

fn comfy_error_detail(error: &ProviderTransportError) -> &'static str {
    match error {
        ProviderTransportError::Status { .. } => "provider non-2xx status",
        ProviderTransportError::Connect => "no byte accepted (connect refused)",
        ProviderTransportError::Tls => "no byte accepted (tls)",
        ProviderTransportError::BodyLimit => "response exceeded bound",
        ProviderTransportError::Malformed => "response unparseable",
        ProviderTransportError::Timeout | ProviderTransportError::AmbiguousAcceptance => {
            "handoff ambiguous"
        }
    }
}

fn comfy_evidence(class: &[u8], detail: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(class);
    out.push(0);
    let bounded = detail
        .chars()
        .take(EVIDENCE_DETAIL_MAX_CHARS)
        .collect::<String>();
    out.extend_from_slice(bounded.as_bytes());
    out
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Crate-internal test doubles for the ComfyUI dispatch path.
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    pub(crate) struct ScriptedComfyuiTransport {
        outcomes: Mutex<VecDeque<Result<ProviderTransportOutcome, ProviderTransportError>>>,
        calls: Mutex<Vec<ComfyHttpRequest>>,
    }

    impl ScriptedComfyuiTransport {
        pub(crate) fn new(
            outcomes: Vec<Result<ProviderTransportOutcome, ProviderTransportError>>,
        ) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn calls(&self) -> Vec<ComfyHttpRequest> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl comfyui_adapter_sealed::Sealed for ScriptedComfyuiTransport {}

    #[async_trait::async_trait]
    impl ComfyuiTransport for ScriptedComfyuiTransport {
        async fn call(
            &self,
            request: ComfyHttpRequest,
        ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
            self.calls.lock().unwrap().push(request);
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted transport exhausted")
        }
    }

    /// A plan source with fixed handoff/reconcile/cancel resolutions.
    pub(crate) struct FixedComfyuiPlanSource {
        pub(crate) handoff: ComfyuiImagesPlanResolution,
        pub(crate) reconcile: Option<ComfyuiReconcileInput>,
        pub(crate) cancel: Option<ComfyuiCancelInput>,
    }

    impl comfyui_adapter_sealed::Sealed for FixedComfyuiPlanSource {}

    #[async_trait::async_trait]
    impl ComfyuiImagesPlanSource for FixedComfyuiPlanSource {
        async fn resolve_handoff(
            &self,
            _request: &ImageGenerationHandoffRequest,
        ) -> ComfyuiImagesPlanResolution {
            self.handoff.clone()
        }
        async fn resolve_reconcile(
            &self,
            _request: &ImageGenerationReconcileRequest,
        ) -> Option<ComfyuiReconcileInput> {
            self.reconcile.clone()
        }
        async fn resolve_cancel(
            &self,
            _request: &ImageGenerationCancelRequest,
        ) -> Option<ComfyuiCancelInput> {
            self.cancel.clone()
        }
    }

    pub(crate) fn sample_attempt_input() -> ComfyuiImagesAttemptInput {
        ComfyuiImagesAttemptInput {
            prompt_graph: serde_json::json!({ "3": { "class_type": "KSampler", "inputs": {} } }),
            client_id: "cockpit-attempt-1".to_string(),
        }
    }

    pub(crate) fn resolved_handoff_source() -> FixedComfyuiPlanSource {
        FixedComfyuiPlanSource {
            handoff: ComfyuiImagesPlanResolution::Resolved(Box::new(sample_attempt_input())),
            reconcile: None,
            cancel: None,
        }
    }

    /// A `POST /prompt` success body carrying a prompt id.
    pub(crate) fn sample_prompt_accept_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "prompt_id": "prompt-123" })).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::Pin;

    use super::test_support::*;
    use super::*;
    use crate::image_generation_comfyui::ComfyCancellationCapability;
    use crate::image_generation_runtime::RuntimeError;

    struct FixedDnsResolver {
        answers: Vec<IpAddr>,
    }

    impl DnsResolver for FixedDnsResolver {
        fn resolve<'a>(
            &'a self,
            _hostname: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>> {
            let answers = self.answers.clone();
            Box::pin(async move { Ok(answers) })
        }
    }

    fn handoff_request() -> ImageGenerationHandoffRequest {
        ImageGenerationHandoffRequest {
            job_id: uuid::Uuid::now_v7(),
            owner_session_id: uuid::Uuid::now_v7(),
            target_id: "fixture-target".into(),
            slot_id: uuid::Uuid::now_v7(),
            attempt_number: 1,
            external_operation_id: uuid::Uuid::now_v7(),
            provider_request_identity: "request:1".into(),
            provider_idempotency_identity: "idempotency:1".into(),
            sealed_prompt: crate::image_generation_job::SealedImageGenerationPromptV1::bind(
                "fixture prompt".into(),
            )
            .unwrap(),
        }
    }

    fn cancel_request_fixture() -> ImageGenerationCancelRequest {
        ImageGenerationCancelRequest {
            job_id: uuid::Uuid::now_v7(),
            slot_id: uuid::Uuid::now_v7(),
            attempt_number: 1,
            external_operation_id: uuid::Uuid::now_v7(),
            provider_request_identity: "request:1".into(),
        }
    }

    #[test]
    fn vetted_transport_allows_local_http_and_redacts_headers() {
        let transport = ComfyuiHttpTransport::vetted(
            "http://127.0.0.1:8188",
            None,
            ImageLocationClass::Local,
            Arc::new(FixedDnsResolver {
                answers: vec!["127.0.0.1".parse().unwrap()],
            }),
            vec![("authorization".to_string(), "secret-token".to_string())],
        )
        .expect("vetted transport accepts a local http origin");
        let rendered = format!("{transport:?}");
        assert!(
            !rendered.contains("secret-token"),
            "credential leaked: {rendered}"
        );
    }

    #[test]
    fn vetted_rejects_authority_changing_path_prefix() {
        for bad in [
            "https://attacker",
            "//attacker",
            "http://evil@x",
            "no-leading-slash",
        ] {
            let err = ComfyuiHttpTransport::vetted(
                "http://127.0.0.1:8188",
                Some(bad),
                ImageLocationClass::Local,
                Arc::new(FixedDnsResolver {
                    answers: vec!["127.0.0.1".parse().unwrap()],
                }),
                Vec::new(),
            )
            .unwrap_err();
            assert_eq!(
                err,
                ProviderTransportConfigError::ForbiddenOriginComponent,
                "path prefix {bad:?} must be rejected"
            );
        }
        assert!(
            ComfyuiHttpTransport::vetted(
                "http://127.0.0.1:8188",
                Some("/comfy"),
                ImageLocationClass::Local,
                Arc::new(FixedDnsResolver {
                    answers: vec!["127.0.0.1".parse().unwrap()],
                }),
                Vec::new(),
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn handoff_accepts_prompt_id_and_posts_to_prompt() {
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![Ok(
            ProviderTransportOutcome {
                status: 200,
                body: sample_prompt_accept_body(),
            },
        )]));
        let adapter =
            ComfyuiImagesAdapter::new(transport.clone(), Arc::new(resolved_handoff_source()));
        let result = adapter.handoff(&handoff_request()).await;
        assert!(matches!(
            result,
            ImageGenerationHandoffResult::Accepted { .. }
        ));
        let calls = transport.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/prompt");
        assert_eq!(calls[0].method, ComfyMethod::Post);
        assert_eq!(calls[0].body_limit, MAX_PROMPT_RESPONSE_BYTES);
    }

    #[tokio::test]
    async fn handoff_2xx_without_prompt_id_is_submission_unknown() {
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![Ok(
            ProviderTransportOutcome {
                status: 200,
                body: serde_json::to_vec(&serde_json::json!({ "queued": true })).unwrap(),
            },
        )]));
        let adapter = ComfyuiImagesAdapter::new(transport, Arc::new(resolved_handoff_source()));
        assert!(matches!(
            adapter.handoff(&handoff_request()).await,
            ImageGenerationHandoffResult::SubmissionUnknown { .. }
        ));
    }

    #[tokio::test]
    async fn handoff_status_is_definitive_rejection() {
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![Err(
            ProviderTransportError::Status {
                status: 400,
                body: Vec::new(),
            },
        )]));
        let adapter = ComfyuiImagesAdapter::new(transport, Arc::new(resolved_handoff_source()));
        assert!(matches!(
            adapter.handoff(&handoff_request()).await,
            ImageGenerationHandoffResult::DefinitivelyRejected { .. }
        ));
    }

    #[tokio::test]
    async fn handoff_ambiguous_is_submission_unknown() {
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![Err(
            ProviderTransportError::Timeout,
        )]));
        let adapter = ComfyuiImagesAdapter::new(transport, Arc::new(resolved_handoff_source()));
        assert!(matches!(
            adapter.handoff(&handoff_request()).await,
            ImageGenerationHandoffResult::SubmissionUnknown { .. }
        ));
    }

    #[tokio::test]
    async fn reconcile_downloads_view_with_named_bound_and_reports_accepted() {
        // History says completed with one declared output; the /view download
        // must be issued with the MAX_VIEW_DOWNLOAD_BYTES bound.
        let history_body = serde_json::to_vec(&serde_json::json!({
            "prompt-123": {
                "outputs": { "9": { "images": [{ "filename": "a.png", "subfolder": "", "type": "output" }] } },
                "status": { "completed": true }
            }
        }))
        .unwrap();
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![
            Ok(ProviderTransportOutcome {
                status: 200,
                body: history_body,
            }),
            Ok(ProviderTransportOutcome {
                status: 200,
                body: vec![0x89, b'P', b'N', b'G'],
            }),
        ]));
        let plan = FixedComfyuiPlanSource {
            handoff: ComfyuiImagesPlanResolution::Unresolvable {
                safe_reason: "n/a".into(),
            },
            reconcile: Some(ComfyuiReconcileInput {
                prompt_id: "prompt-123".to_string(),
                declared_outputs: vec![WorkflowOutput {
                    node_id: "9".to_string(),
                    output: "images".to_string(),
                    value_type: cockpit_config::config::image_generation::WorkflowValueType::Image,
                }],
            }),
            cancel: None,
        };
        let adapter = ComfyuiImagesAdapter::new(transport.clone(), Arc::new(plan));
        let request = ImageGenerationReconcileRequest {
            job_id: uuid::Uuid::now_v7(),
            slot_id: uuid::Uuid::now_v7(),
            attempt_number: 1,
            external_operation_id: uuid::Uuid::now_v7(),
            provider_request_identity: "request:1".into(),
            provider_idempotency_identity: "idempotency:1".into(),
        };
        let result = adapter.reconcile(&request).await;
        assert!(matches!(
            result,
            ImageGenerationReconcileResult::AuthoritativeAccepted { .. }
        ));
        let calls = transport.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].path, "/history/prompt-123");
        assert_eq!(calls[0].body_limit, MAX_HISTORY_RESPONSE_BYTES);
        assert_eq!(calls[1].path, "/view");
        assert_eq!(calls[1].body_limit, MAX_VIEW_DOWNLOAD_BYTES);
    }

    #[tokio::test]
    async fn cancel_job_scoped_maps_cancelled_ack() {
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![Ok(
            ProviderTransportOutcome {
                status: 200,
                body: serde_json::to_vec(&serde_json::json!({ "cancelled": true })).unwrap(),
            },
        )]));
        let plan = FixedComfyuiPlanSource {
            handoff: ComfyuiImagesPlanResolution::Unresolvable {
                safe_reason: "n/a".into(),
            },
            reconcile: None,
            cancel: Some(ComfyuiCancelInput {
                capability: ComfyCancellationCapability::JobScopedCancel,
                prompt_id: None,
                job_id: Some("job-7".to_string()),
            }),
        };
        let adapter = ComfyuiImagesAdapter::new(transport.clone(), Arc::new(plan));
        let result = adapter.cancel(&cancel_request_fixture()).await;
        assert!(matches!(
            result,
            ImageGenerationCancelResult::Cancelled { .. }
        ));
        assert_eq!(transport.calls()[0].path, "/api/jobs/job-7/cancel");
    }

    #[tokio::test]
    async fn cancel_job_scoped_false_ack_is_too_late() {
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![Ok(
            ProviderTransportOutcome {
                status: 200,
                body: serde_json::to_vec(&serde_json::json!({ "cancelled": false })).unwrap(),
            },
        )]));
        let plan = FixedComfyuiPlanSource {
            handoff: ComfyuiImagesPlanResolution::Unresolvable {
                safe_reason: "n/a".into(),
            },
            reconcile: None,
            cancel: Some(ComfyuiCancelInput {
                capability: ComfyCancellationCapability::JobScopedCancel,
                prompt_id: None,
                job_id: Some("job-7".to_string()),
            }),
        };
        let adapter = ComfyuiImagesAdapter::new(transport, Arc::new(plan));
        assert!(matches!(
            adapter.cancel(&cancel_request_fixture()).await,
            ImageGenerationCancelResult::TooLateOrAccepted { .. }
        ));
    }
}
