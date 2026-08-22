//! Gemini Interactions image-generation dispatch adapter (AC2).
//!
//! Wraps the pure Interactions request builder and response extractor from
//! [`crate::image_generation_runtime::gemini`] behind the sealed
//! [`ImageGenerationAdapter`] dispatch trait, submitting exactly one bounded
//! `POST /v1beta/interactions` request through the shared pinned/vetted
//! transport. Billing-safe semantics: a 2xx is an accepted (paid) submission;
//! a pre-handoff connect/TLS failure is a definitive rejection safe to resubmit;
//! a timeout/reset after the request was written is `submission_unknown`.
//!
//! The `x-goog-api-key` credential lives only in the production transport's
//! sensitive header; it is never hardcoded, logged, or rendered in `Debug`, and
//! never appears in handoff evidence.

use std::sync::Arc;

use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};

use crate::image_generation::http_transport::{
    ProviderTransportConfigError, VettedHttpClient, validate_https_origin,
};
use crate::image_generation::transport::{
    ProviderTransportError, ProviderTransportOutcome, SubmissionDisposition,
};
use crate::image_generation_job::{
    ImageGenerationAdapter, ImageGenerationCancelRequest, ImageGenerationCancelResult,
    ImageGenerationHandoffRequest, ImageGenerationHandoffResult, ImageGenerationReconcileRequest,
    ImageGenerationReconcileResult, image_generation_adapter_sealed,
};
use crate::image_generation_runtime::AddressClass;
use crate::image_generation_runtime::DnsResolver;
use crate::image_generation_runtime::gemini::{
    API_KEY_HEADER, GeminiInteractionsRequestInput, GeminiInteractionsResponse, INTERACTIONS_ROUTE,
    MAX_INLINE_IMAGE_BYTES, build_interactions_request, extract_images,
};

/// The response-body bound for `POST /v1beta/interactions`, enforced while
/// reading. A completed interaction may carry up to
/// [`crate::image_generation_runtime::gemini::MAX_REFERENCE_IMAGES`] inline
/// images; the bound is a generous multiple of the per-image inline cap plus a
/// metadata allowance, so an oversized response is refused before it is
/// buffered.
pub const MAX_INTERACTIONS_RESPONSE_BYTES: usize = 4 * MAX_INLINE_IMAGE_BYTES + 64 * 1024;

/// The evidence-detail character bound (bytes are ASCII-derived, secret-free).
const EVIDENCE_DETAIL_MAX_CHARS: usize = 512;

mod gemini_adapter_sealed {
    pub trait Sealed {}
}

/// Transport seam for the Gemini Interactions API. Production wires this to
/// [`GeminiImagesHttpTransport`]; tests wire a scripted transport. The seam is
/// the only place a request byte leaves the process; the `x-goog-api-key`
/// credential is applied here.
#[async_trait::async_trait]
pub trait GeminiImagesTransport: gemini_adapter_sealed::Sealed + Send + Sync {
    async fn submit(
        &self,
        body: Vec<u8>,
    ) -> Result<ProviderTransportOutcome, ProviderTransportError>;
}

/// A production pinned HTTPS transport bound to one Gemini origin.
///
/// Constructible only through [`GeminiImagesHttpTransport::vetted`]. The API key
/// is caller-supplied (never hardcoded), held sensitive, and redacted in
/// `Debug`. A `POST` is always sent to the fixed [`INTERACTIONS_ROUTE`] on the
/// configured origin.
pub struct GeminiImagesHttpTransport {
    origin: Url,
    api_key: HeaderValue,
    dns: Arc<dyn DnsResolver>,
    body_limit: usize,
}

impl std::fmt::Debug for GeminiImagesHttpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeminiImagesHttpTransport")
            .field("origin", &self.origin.as_str())
            .field("api_key", &"<redacted>")
            .field("body_limit", &self.body_limit)
            .finish()
    }
}

impl GeminiImagesHttpTransport {
    pub fn vetted(
        origin: &str,
        api_key: &str,
        dns: Arc<dyn DnsResolver>,
        body_limit: usize,
    ) -> Result<Self, ProviderTransportConfigError> {
        let origin = validate_https_origin(origin)?;
        if body_limit == 0 {
            return Err(ProviderTransportConfigError::EmptyBodyLimit);
        }
        let mut api_key = HeaderValue::from_str(api_key)
            .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
        api_key.set_sensitive(true);
        Ok(Self {
            origin,
            api_key,
            dns,
            body_limit,
        })
    }
}

impl gemini_adapter_sealed::Sealed for GeminiImagesHttpTransport {}

#[async_trait::async_trait]
impl GeminiImagesTransport for GeminiImagesHttpTransport {
    async fn submit(
        &self,
        body: Vec<u8>,
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        let url = self
            .origin
            .join(INTERACTIONS_ROUTE.trim_start_matches('/'))
            .map_err(|_| ProviderTransportError::Connect)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(API_KEY_HEADER),
            self.api_key.clone(),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        VettedHttpClient::new(self.dns.clone(), AddressClass::PublicRemote)
            .execute(Method::POST, &url, headers, Some(body), self.body_limit)
            .await
    }
}

/// The immutable per-attempt inputs the Gemini adapter needs to build one
/// submission.
#[derive(Debug, Clone)]
pub struct GeminiImagesAttemptInput {
    pub request: GeminiInteractionsRequestInput,
}

/// Resolves the immutable per-attempt plan from a dispatch handoff request.
#[async_trait::async_trait]
pub trait GeminiImagesPlanSource: gemini_adapter_sealed::Sealed + Send + Sync {
    async fn resolve(&self, request: &ImageGenerationHandoffRequest) -> GeminiImagesPlanResolution;
}

/// Outcome of resolving the per-attempt plan.
#[derive(Debug, Clone)]
pub enum GeminiImagesPlanResolution {
    Resolved(Box<GeminiImagesAttemptInput>),
    Unresolvable { safe_reason: String },
}

/// The Gemini Images dispatch adapter. Implements the sealed
/// [`ImageGenerationAdapter`].
pub struct GeminiImagesAdapter {
    transport: Arc<dyn GeminiImagesTransport>,
    plan_source: Arc<dyn GeminiImagesPlanSource>,
}

impl GeminiImagesAdapter {
    pub fn new(
        transport: Arc<dyn GeminiImagesTransport>,
        plan_source: Arc<dyn GeminiImagesPlanSource>,
    ) -> Self {
        Self {
            transport,
            plan_source,
        }
    }
}

impl image_generation_adapter_sealed::Sealed for GeminiImagesAdapter {}

#[async_trait::async_trait]
impl ImageGenerationAdapter for GeminiImagesAdapter {
    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        let input = match self.plan_source.resolve(request).await {
            GeminiImagesPlanResolution::Resolved(input) => *input,
            GeminiImagesPlanResolution::Unresolvable { safe_reason } => {
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: gemini_redacted_evidence(b"plan_unresolvable", &safe_reason),
                };
            }
        };
        // The pure builder validates the request against the checked-in catalog;
        // a build failure means no request was ever sent.
        let built = match build_interactions_request(&input.request) {
            Ok(built) => built,
            Err(error) => {
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: gemini_redacted_evidence(b"request_build", &error.to_string()),
                };
            }
        };
        let body = match serde_json::to_vec(&built) {
            Ok(body) => body,
            Err(_) => {
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: gemini_redacted_evidence(b"request_serialize", "serialize failed"),
                };
            }
        };
        let planned = input.request.planned_outputs;
        match self.transport.submit(body).await {
            Ok(outcome) => {
                // A 2xx is an accepted (and likely paid) submission. Whether the
                // interaction has already completed only decorates the evidence;
                // it never demotes an accepted submission to a resubmittable
                // rejection.
                let detail = summarize_2xx(&outcome, planned);
                ImageGenerationHandoffResult::Accepted {
                    evidence: gemini_redacted_evidence(b"accepted", &detail),
                }
            }
            Err(error) => match error.submission_disposition() {
                SubmissionDisposition::DefinitivelyRejected => {
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: gemini_redacted_evidence(
                            b"definitive_nonacceptance",
                            gemini_error_detail(&error),
                        ),
                    }
                }
                SubmissionDisposition::SubmissionUnknown => {
                    ImageGenerationHandoffResult::SubmissionUnknown {
                        evidence: gemini_redacted_evidence(
                            b"post_handoff_ambiguous",
                            "handoff accepted",
                        ),
                    }
                }
            },
        }
    }

    async fn reconcile(
        &self,
        _request: &ImageGenerationReconcileRequest,
    ) -> ImageGenerationReconcileResult {
        // Reconciling a submission-unknown Gemini interaction requires a
        // provider operation-status fetch that the daemon-integration layer
        // owns; until then we report an honest unknown rather than invent one.
        ImageGenerationReconcileResult::OutcomeUnknown {
            evidence: gemini_redacted_evidence(
                b"reconcile_unavailable",
                "interaction status fetch not wired in this layer",
            ),
        }
    }

    async fn cancel(&self, _request: &ImageGenerationCancelRequest) -> ImageGenerationCancelResult {
        // The Gemini Interactions API exposes no cancel endpoint in this layer.
        ImageGenerationCancelResult::OutcomeUnknown {
            evidence: gemini_redacted_evidence(b"cancel_unavailable", "no cancel endpoint"),
        }
    }
}

/// Summarize a 2xx body for redacted evidence. Never surfaces provider free text
/// or image bytes: only a stable completed/pending marker and the count of
/// extracted image slots (bounded by the planned count).
fn summarize_2xx(outcome: &ProviderTransportOutcome, planned: u32) -> String {
    match serde_json::from_slice::<GeminiInteractionsResponse>(&outcome.body) {
        Ok(response) => match extract_images(&response, planned) {
            Ok(result) => format!(
                "status={} completed images={}",
                outcome.status,
                result.images.len()
            ),
            // A 2xx whose interaction is not yet completed (or whose steps do
            // not yet carry output) is still an accepted submission.
            Err(_) => format!("status={} pending", outcome.status),
        },
        Err(_) => format!("status={} unparsed", outcome.status),
    }
}

fn gemini_error_detail(error: &ProviderTransportError) -> &'static str {
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

fn gemini_redacted_evidence(class: &[u8], detail: &str) -> Vec<u8> {
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
    //! Crate-internal test doubles for the Gemini dispatch path.
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use base64::Engine as _;

    use super::*;

    pub(crate) struct ScriptedGeminiTransport {
        outcomes: Mutex<VecDeque<Result<ProviderTransportOutcome, ProviderTransportError>>>,
        submissions: Mutex<Vec<Vec<u8>>>,
    }

    impl ScriptedGeminiTransport {
        pub(crate) fn new(
            outcomes: Vec<Result<ProviderTransportOutcome, ProviderTransportError>>,
        ) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                submissions: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn submissions(&self) -> Vec<Vec<u8>> {
            self.submissions.lock().unwrap().clone()
        }
    }

    impl gemini_adapter_sealed::Sealed for ScriptedGeminiTransport {}

    #[async_trait::async_trait]
    impl GeminiImagesTransport for ScriptedGeminiTransport {
        async fn submit(
            &self,
            body: Vec<u8>,
        ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
            self.submissions.lock().unwrap().push(body);
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted transport exhausted")
        }
    }

    pub(crate) struct FixedGeminiPlanSource {
        input: GeminiImagesAttemptInput,
    }

    impl FixedGeminiPlanSource {
        pub(crate) fn new(input: GeminiImagesAttemptInput) -> Self {
            Self { input }
        }
    }

    impl gemini_adapter_sealed::Sealed for FixedGeminiPlanSource {}

    #[async_trait::async_trait]
    impl GeminiImagesPlanSource for FixedGeminiPlanSource {
        async fn resolve(
            &self,
            _request: &ImageGenerationHandoffRequest,
        ) -> GeminiImagesPlanResolution {
            GeminiImagesPlanResolution::Resolved(Box::new(self.input.clone()))
        }
    }

    /// A valid prompt-only Gemini attempt input against a catalog model.
    pub(crate) fn sample_attempt_input() -> GeminiImagesAttemptInput {
        let model = crate::image_generation_runtime::gemini::catalog_model_names()[0].to_string();
        GeminiImagesAttemptInput {
            request: GeminiInteractionsRequestInput {
                model,
                prompt: "a serene mountain lake at dawn".to_string(),
                references: Vec::new(),
                mime_type: None,
                aspect_ratio: None,
                image_size: None,
                planned_outputs: 1,
            },
        }
    }

    /// A completed single-image Interactions response for the sample plan.
    pub(crate) fn sample_success_body() -> Vec<u8> {
        let mut png = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(1, 1)
            .write_to(&mut png, image::ImageFormat::Png)
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(png.into_inner());
        serde_json::to_vec(&serde_json::json!({
            "id": "interaction-1",
            "status": "completed",
            "steps": [{
                "type": "model_output",
                "content": [{ "type": "image", "data": b64, "mime_type": "image/png" }]
            }]
        }))
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::Pin;

    use super::test_support::*;
    use super::*;
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

    #[test]
    fn vetted_builder_redacts_api_key_in_debug() {
        let transport = GeminiImagesHttpTransport::vetted(
            "https://generativelanguage.googleapis.com",
            "AIza-super-secret",
            Arc::new(FixedDnsResolver {
                answers: vec!["93.184.216.34".parse().unwrap()],
            }),
            1024,
        )
        .expect("vetted builder accepts a clean https origin");
        let rendered = format!("{transport:?}");
        assert!(
            !rendered.contains("AIza-super-secret"),
            "credential leaked in Debug: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn vetted_builder_rejects_non_https() {
        assert_eq!(
            GeminiImagesHttpTransport::vetted(
                "http://generativelanguage.googleapis.com",
                "k",
                Arc::new(FixedDnsResolver { answers: vec![] }),
                1024,
            )
            .unwrap_err(),
            ProviderTransportConfigError::NotHttps
        );
    }

    fn adapter_with(
        outcome: Result<ProviderTransportOutcome, ProviderTransportError>,
    ) -> (GeminiImagesAdapter, Arc<ScriptedGeminiTransport>) {
        let transport = Arc::new(ScriptedGeminiTransport::new(vec![outcome]));
        let adapter = GeminiImagesAdapter::new(
            transport.clone(),
            Arc::new(FixedGeminiPlanSource::new(sample_attempt_input())),
        );
        (adapter, transport)
    }

    fn handoff_request() -> ImageGenerationHandoffRequest {
        ImageGenerationHandoffRequest {
            job_id: uuid::Uuid::now_v7(),
            slot_id: uuid::Uuid::now_v7(),
            attempt_number: 1,
            external_operation_id: uuid::Uuid::now_v7(),
            provider_request_identity: "request:1".into(),
            provider_idempotency_identity: "idempotency:1".into(),
        }
    }

    #[tokio::test]
    async fn handoff_accepts_completed_2xx_and_sends_a_request() {
        let (adapter, transport) = adapter_with(Ok(ProviderTransportOutcome {
            status: 200,
            body: sample_success_body(),
        }));
        let result = adapter.handoff(&handoff_request()).await;
        assert!(matches!(
            result,
            ImageGenerationHandoffResult::Accepted { .. }
        ));
        // Non-vacuity: the adapter built and sent exactly one request body
        // carrying the prompt text through the Interactions `input` array.
        let submissions = transport.submissions();
        assert_eq!(submissions.len(), 1);
        assert!(
            submissions[0]
                .windows(b"serene mountain lake".len())
                .any(|w| w == b"serene mountain lake"),
            "request body must carry the prompt text"
        );
    }

    #[tokio::test]
    async fn handoff_maps_status_to_definitive_rejection() {
        let (adapter, _t) = adapter_with(Err(ProviderTransportError::Status {
            status: 302,
            body: Vec::new(),
        }));
        assert!(matches!(
            adapter.handoff(&handoff_request()).await,
            ImageGenerationHandoffResult::DefinitivelyRejected { .. }
        ));
    }

    #[tokio::test]
    async fn handoff_maps_ambiguous_to_submission_unknown() {
        let (adapter, _t) = adapter_with(Err(ProviderTransportError::AmbiguousAcceptance));
        assert!(matches!(
            adapter.handoff(&handoff_request()).await,
            ImageGenerationHandoffResult::SubmissionUnknown { .. }
        ));
    }
}
