//! Crate-internal test doubles for the OpenAI Images dispatch path.
//!
//! These live outside the private `tests` module so the dispatcher integration
//! tests in `image_generation_job` can construct a real [`OpenaiImagesAdapter`]
//! backed by a scripted transport and scripted plan source without any network.

use std::collections::VecDeque;
use std::sync::Mutex;

use base64::Engine as _;

use super::preflight::{PreflightInput, PreflightPlan, preflight};
use super::{
    OpenaiImagesPlanResolution, OpenaiImagesPlanSource, OpenaiImagesRoute, OpenaiImagesTransport,
    openai_images_adapter_sealed,
};
use crate::image_generation::transport::{ProviderTransportError, ProviderTransportOutcome};
use crate::image_generation_job::ImageGenerationHandoffRequest;

/// A transport that returns scripted outcomes in FIFO order and records every
/// submission so a test can prove the adapter actually built and sent a request.
pub(crate) struct ScriptedProviderTransport {
    outcomes: Mutex<VecDeque<Result<ProviderTransportOutcome, ProviderTransportError>>>,
    submissions: Mutex<Vec<(OpenaiImagesRoute, String, Vec<u8>)>>,
}

impl ScriptedProviderTransport {
    pub(crate) fn new(
        outcomes: Vec<Result<ProviderTransportOutcome, ProviderTransportError>>,
    ) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into()),
            submissions: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn submissions(&self) -> Vec<(OpenaiImagesRoute, String, Vec<u8>)> {
        self.submissions.lock().unwrap().clone()
    }
}

impl openai_images_adapter_sealed::Sealed for ScriptedProviderTransport {}

#[async_trait::async_trait]
impl OpenaiImagesTransport for ScriptedProviderTransport {
    async fn submit(
        &self,
        route: OpenaiImagesRoute,
        content_type: &str,
        body: &[u8],
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        self.submissions
            .lock()
            .unwrap()
            .push((route, content_type.to_string(), body.to_vec()));
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted transport exhausted")
    }
}

/// A plan source that resolves every request to the same fixed plan.
pub(crate) struct FixedPlanSource {
    plan: PreflightPlan,
}

impl FixedPlanSource {
    pub(crate) fn new(plan: PreflightPlan) -> Self {
        Self { plan }
    }
}

impl openai_images_adapter_sealed::Sealed for FixedPlanSource {}

#[async_trait::async_trait]
impl OpenaiImagesPlanSource for FixedPlanSource {
    async fn resolve(
        &self,
        _request: &ImageGenerationHandoffRequest,
    ) -> OpenaiImagesPlanResolution {
        OpenaiImagesPlanResolution::Resolved(Box::new(self.plan.clone()))
    }
}

/// A plan source that never resolves, exercising the "no byte sent" path.
pub(crate) struct UnresolvablePlanSource {
    reason: String,
}

impl UnresolvablePlanSource {
    pub(crate) fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
        }
    }
}

impl openai_images_adapter_sealed::Sealed for UnresolvablePlanSource {}

#[async_trait::async_trait]
impl OpenaiImagesPlanSource for UnresolvablePlanSource {
    async fn resolve(
        &self,
        _request: &ImageGenerationHandoffRequest,
    ) -> OpenaiImagesPlanResolution {
        OpenaiImagesPlanResolution::Unresolvable {
            safe_reason: self.reason.clone(),
        }
    }
}

/// A valid single-output prompt-only plan (`gpt-image-1.5`, PNG) whose route is
/// [`OpenaiImagesRoute::Generations`].
pub(crate) fn sample_generation_plan() -> PreflightPlan {
    let input = PreflightInput {
        model: "gpt-image-1.5".into(),
        prompt: "a serene mountain lake at dawn".into(),
        n: 1,
        width: 1024,
        height: 1024,
        quality: "auto".into(),
        background: "auto".into(),
        output_format: "png".into(),
        moderation: "auto".into(),
        compression: None,
        input_fidelity: Some("high".into()),
    };
    preflight(&input, &[]).expect("sample plan should preflight")
}

/// A minimal valid 1x1 PNG.
fn one_pixel_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, // IHDR
        0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x62, 0x00, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x01, 0xC1, 0xA0, 0x2D, 0x2A, // IDAT
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82, // IEND
    ]
}

/// A successful single-image OpenAI Images response body for the sample plan.
pub(crate) fn sample_success_body() -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(one_pixel_png());
    serde_json::to_vec(&serde_json::json!({ "data": [{ "b64_json": b64 }] })).unwrap()
}
