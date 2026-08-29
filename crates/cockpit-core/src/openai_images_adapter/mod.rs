//! OpenAI Images API generation/edit adapter.
//!
//! Implements adapter kind `openai_images` against the configured origin.
//! Prompt-only plans use `POST /v1/images/generations`. Plans with one or more
//! authorized typed image references use bounded multipart `POST /v1/images/edits`.
//! Only `data[].b64_json` is parsed into bounded bytes; there is no URL-output
//! branch. Automatic submission retry is forbidden unless transport evidence
//! proves no request byte was accepted; timeout or reset after handoff becomes
//! `submission_unknown`.
//!
//! Generated request/response DTOs are kept separate from inference DTOs. The
//! catalog is stored as typed descriptors with an explicit revision, not
//! scattered model-name conditionals. Credential data and raw reference bytes
//! are absent from logs, journal metadata, and errors.

mod catalog;
mod dto;
mod http_transport;
mod preflight;
mod response;
mod wire;

#[cfg(test)]
pub(crate) mod test_support;

pub use catalog::{
    CATALOG_PROVENANCE_DATE, CATALOG_REVISION, ImageModelDescriptor, ImageModelIdentity,
    OpenaiImagesCatalog,
};
pub use dto::{
    EditMultipartPart, EditRequest, GenerationRequest, ImagesResponseItem, ParsedImageSlot,
    ParsedImagesResponse, ResponseBackground, ResponseOutputFormat, ResponseQuality,
};
pub use http_transport::{OpenaiImagesHttpTransport, OpenaiImagesTransportConfigError};
pub use preflight::{
    PreflightFailure, PreflightInput, PreflightPlan, PreflightReference, PreflightResult, preflight,
};
pub use response::{DecodeLimit, ResponseParseFailure, parse_response};
pub use wire::{
    GenerationWireBody, MultipartWireBody, WireBody, WireEncodingFailure, encode_generation,
    encode_multipart,
};

use std::sync::Arc;

use anyhow::Result;
use uuid::Uuid;

use crate::image_generation::transport::{ProviderTransportError, ProviderTransportOutcome};
use crate::image_generation_job::{
    ImageGenerationAdapter, ImageGenerationCancelRequest, ImageGenerationCancelResult,
    ImageGenerationHandoffRequest, ImageGenerationHandoffResult, ImageGenerationReconcileRequest,
    ImageGenerationReconcileResult, image_generation_adapter_sealed,
};

/// Bounded base64 length checked before decode; decoded bytes capped by
/// canonical output limits. See [`response::DecodeLimit`].
pub const MAX_BASE64_LENGTH_BYTES: usize = 64 * 1024 * 1024;

/// Multipart parts are 1–16 bounded typed media values with deterministic
/// order and provider field names.
pub const MAX_EDIT_REFERENCES: usize = 16;

/// `n` is an integer 1–10 and must equal the immutable planned slot count.
pub const MAX_OUTPUTS_PER_REQUEST: u32 = 10;

/// The normalized prompt is at most 32,000 Unicode scalar values and 128,000
/// UTF-8 bytes.
pub const MAX_PROMPT_UNICODE_SCALARS: usize = 32_000;
pub const MAX_PROMPT_UTF8_BYTES: usize = 128_000;

pub(crate) mod openai_images_adapter_sealed {
    pub trait Sealed {}
}

/// Transport seam injected into the adapter. Production wires this to
/// [`OpenaiImagesHttpTransport`] (a pinned reqwest client); tests wire
/// deterministic fixtures. The seam is the only place a request byte leaves the
/// process.
#[async_trait::async_trait]
pub trait OpenaiImagesTransport: openai_images_adapter_sealed::Sealed + Send + Sync {
    /// Submits a fully encoded request body. Returns the bounded response on a
    /// 2xx, or a [`ProviderTransportError`] classifying the failure onto the
    /// shared billing-safe transport vocabulary.
    async fn submit(
        &self,
        route: OpenaiImagesRoute,
        content_type: &str,
        body: &[u8],
    ) -> Result<ProviderTransportOutcome, ProviderTransportError>;
}

/// Resolves the immutable per-attempt plan the adapter needs to build one
/// provider request from a dispatch [`ImageGenerationHandoffRequest`], which
/// carries only opaque identities. The production resolver (DB-backed plan
/// lookup keyed by the attempt identity) is supplied by the daemon-integration
/// layer that constructs and installs the adapter; this crate ships the seam
/// plus a scripted resolver for tests. The seam is sealed so only in-crate
/// resolvers can satisfy it.
#[async_trait::async_trait]
pub trait OpenaiImagesPlanSource: openai_images_adapter_sealed::Sealed + Send + Sync {
    async fn resolve(&self, request: &ImageGenerationHandoffRequest) -> OpenaiImagesPlanResolution;
}

/// Outcome of resolving the per-attempt plan. A resolution failure means no
/// request was ever built or sent, so the dispatch layer treats it as a
/// definitive rejection (no paid submission) — never a submission-unknown.
#[derive(Debug, Clone)]
pub enum OpenaiImagesPlanResolution {
    /// The immutable plan validated into provider request inputs.
    Resolved(Box<PreflightPlan>),
    /// The plan could not be resolved; the reason is redacted and safe to log.
    Unresolvable { safe_reason: String },
}

/// The two routes this adapter ever contacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenaiImagesRoute {
    /// `POST /v1/images/generations` — prompt-only plans.
    Generations,
    /// `POST /v1/images/edits` — plans with one or more typed references.
    Edits,
}

impl OpenaiImagesRoute {
    pub const fn path(self) -> &'static str {
        match self {
            Self::Generations => "/v1/images/generations",
            Self::Edits => "/v1/images/edits",
        }
    }
}

/// Evidence recorded with the spend/journal. Never contains credential data
/// or raw reference bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffEvidence {
    pub route: OpenaiImagesRoute,
    pub status: u16,
    pub provider_request_id: Option<String>,
    pub response_bytes_len: usize,
}

impl HandoffEvidence {
    fn encode(&self) -> Vec<u8> {
        // Stable, redacted evidence encoding. No credentials, no reference
        // bytes, no response bytes.
        let mut out = Vec::new();
        out.extend_from_slice(match self.route {
            OpenaiImagesRoute::Generations => b"openai_images:generations\0",
            OpenaiImagesRoute::Edits => b"openai_images:edits\0",
        });
        out.extend_from_slice(self.status.to_string().as_bytes());
        out.push(0);
        if let Some(id) = &self.provider_request_id {
            out.extend_from_slice(id.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(self.response_bytes_len.to_string().as_bytes());
        out
    }
}

/// Inputs the adapter needs to build and submit one attempt. The dispatcher
/// reconstructs these from the immutable plan before invoking handoff.
#[derive(Debug, Clone)]
pub struct OpenaiImagesAttemptInput {
    pub plan: PreflightPlan,
    pub external_operation_id: Uuid,
    pub provider_request_identity: String,
    pub provider_idempotency_identity: String,
}

/// The OpenAI Images adapter. Implements the sealed [`ImageGenerationAdapter`]
/// dispatch trait (see the `impl` below) with billing-safe submission
/// semantics: a plan is resolved from the dispatch identity, one bounded
/// request is submitted through the pinned transport, and the transport
/// classification maps onto handoff acceptance / definitive rejection /
/// submission-unknown without ever inventing success.
pub struct OpenaiImagesAdapter {
    transport: Arc<dyn OpenaiImagesTransport>,
    plan_source: Arc<dyn OpenaiImagesPlanSource>,
    decode_limit: DecodeLimit,
}

impl openai_images_adapter_sealed::Sealed for OpenaiImagesAdapter {}

impl OpenaiImagesAdapter {
    pub fn new(
        transport: Arc<dyn OpenaiImagesTransport>,
        plan_source: Arc<dyn OpenaiImagesPlanSource>,
        decode_limit: DecodeLimit,
    ) -> Self {
        Self {
            transport,
            plan_source,
            decode_limit,
        }
    }

    /// Builds and submits one attempt. Pure with respect to spend/journal
    /// state: the caller records the returned [`ImageGenerationHandoffResult`].
    pub async fn attempt(
        &self,
        input: &OpenaiImagesAttemptInput,
    ) -> (ImageGenerationHandoffResult, Option<ParsedImagesResponse>) {
        let route = if input.plan.references.is_empty() {
            OpenaiImagesRoute::Generations
        } else {
            OpenaiImagesRoute::Edits
        };
        let encoded = match self.encode(route, input) {
            Ok(value) => value,
            Err(error) => {
                return (
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: redacted_evidence(b"preflight", &error.to_string()),
                    },
                    None,
                );
            }
        };
        let outcome = match self
            .transport
            .submit(route, &encoded.content_type, encoded.body.as_slice())
            .await
        {
            Ok(value) => value,
            Err(ProviderTransportError::Connect | ProviderTransportError::Tls) => {
                // Pre-handoff failure: no request byte was accepted. We do not
                // retry here (the dispatcher owns retry policy); we report a
                // definitive rejection so the slot may resubmit under a fresh
                // idempotency identity. Evidence proves no paid submission.
                return (
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: redacted_evidence(
                            b"pre_handoff_no_byte_accepted",
                            "no byte accepted",
                        ),
                    },
                    None,
                );
            }
            Err(ProviderTransportError::Timeout | ProviderTransportError::AmbiguousAcceptance) => {
                // Post-handoff ambiguity: the request bytes were written and the
                // provider may have processed a paid request. Must be reconciled,
                // never blindly retried.
                return (
                    ImageGenerationHandoffResult::SubmissionUnknown {
                        evidence: redacted_evidence(b"post_handoff_ambiguous", "handoff accepted"),
                    },
                    None,
                );
            }
            Err(ProviderTransportError::Status { status, body: _ }) => {
                return (
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: redacted_evidence(
                            b"definitive_nonacceptance",
                            &format!("status={status}"),
                        ),
                    },
                    None,
                );
            }
            Err(ProviderTransportError::BodyLimit) => {
                return (
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: redacted_evidence(b"body_limit", "response exceeded bound"),
                    },
                    None,
                );
            }
            Err(ProviderTransportError::Malformed) => {
                return (
                    ImageGenerationHandoffResult::DefinitivelyRejected {
                        evidence: redacted_evidence(b"malformed_response", "unparseable"),
                    },
                    None,
                );
            }
        };
        let parsed = match parse_response(&outcome.body, &input.plan, &self.decode_limit) {
            Ok(value) => value,
            Err(error) => {
                // The provider accepted the request (paid) but returned invalid
                // output. This is a stable per-slot failure, not a submission
                // unknown: the spend is committed.
                return (
                    ImageGenerationHandoffResult::Accepted {
                        evidence: redacted_evidence(b"accepted_invalid_output", &error.to_string()),
                    },
                    None,
                );
            }
        };
        let evidence = HandoffEvidence {
            route,
            status: outcome.status,
            provider_request_id: parsed.provider_request_id.clone(),
            response_bytes_len: outcome.body.len(),
        };
        (
            ImageGenerationHandoffResult::Accepted {
                evidence: evidence.encode(),
            },
            Some(parsed),
        )
    }

    fn encode(
        &self,
        route: OpenaiImagesRoute,
        input: &OpenaiImagesAttemptInput,
    ) -> Result<EncodedRequest> {
        match route {
            OpenaiImagesRoute::Generations => {
                let body = encode_generation(input)?;
                Ok(EncodedRequest {
                    content_type: "application/json".to_string(),
                    body: body.into_bytes(),
                })
            }
            OpenaiImagesRoute::Edits => {
                let body = encode_multipart(input)?;
                Ok(EncodedRequest {
                    content_type: body.content_type().to_string(),
                    body: body.into_bytes(),
                })
            }
        }
    }
}

impl image_generation_adapter_sealed::Sealed for OpenaiImagesAdapter {}

/// Sealed dispatch-trait implementation. This is the real
/// `ImageGenerationAdapter` for OpenAI Images, replacing the previous
/// doc-only claim: `handoff` resolves the plan for the dispatch identity and
/// submits exactly one bounded request; `reconcile` and `cancel` are honest
/// no-op-authoritative because the OpenAI Images API is synchronous and exposes
/// no operation-status or cancel endpoint (see each method).
#[async_trait::async_trait]
impl ImageGenerationAdapter for OpenaiImagesAdapter {
    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        let plan = match self.plan_source.resolve(request).await {
            OpenaiImagesPlanResolution::Resolved(plan) => *plan,
            OpenaiImagesPlanResolution::Unresolvable { safe_reason } => {
                // No request was built or sent, so no paid submission occurred:
                // a definitive rejection (safe to resubmit), never a
                // submission-unknown.
                return ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: redacted_evidence(b"plan_unresolvable", &safe_reason),
                };
            }
        };
        let input = OpenaiImagesAttemptInput {
            plan,
            external_operation_id: request.external_operation_id,
            provider_request_identity: request.provider_request_identity.clone(),
            provider_idempotency_identity: request.provider_idempotency_identity.clone(),
        };
        let (result, _parsed) = self.attempt(&input).await;
        result
    }

    async fn reconcile(
        &self,
        _request: &ImageGenerationReconcileRequest,
    ) -> ImageGenerationReconcileResult {
        // OpenAI Images generations/edits are synchronous request/response: the
        // acceptance outcome is known at handoff and there is no server-side
        // operation to re-query. A submission-unknown attempt therefore cannot
        // be authoritatively reconciled without risking a duplicate paid
        // submission, so we report an unknown outcome rather than invent one.
        ImageGenerationReconcileResult::OutcomeUnknown {
            evidence: redacted_evidence(
                b"reconcile_unavailable",
                "openai images api is synchronous; no operation-status endpoint",
            ),
        }
    }

    async fn cancel(&self, _request: &ImageGenerationCancelRequest) -> ImageGenerationCancelResult {
        // There is no OpenAI Images cancel endpoint. A synchronous submission
        // has already resolved by the time a cancel could run, so we report an
        // unknown outcome rather than claim a cancellation that did not happen.
        ImageGenerationCancelResult::OutcomeUnknown {
            evidence: redacted_evidence(
                b"cancel_unavailable",
                "openai images api is synchronous; no cancel endpoint",
            ),
        }
    }
}

struct EncodedRequest {
    content_type: String,
    body: Vec<u8>,
}

fn redacted_evidence(class: &[u8], detail: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(class);
    out.push(0);
    // Detail is bounded and contains no secrets or reference bytes.
    let bounded = detail.chars().take(512).collect::<String>();
    out.extend_from_slice(bounded.as_bytes());
    out
}

#[cfg(test)]
mod tests;
