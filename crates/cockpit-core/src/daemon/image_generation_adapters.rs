//! Session-owned construction of concrete image-generation dispatch adapters.
//!
//! A daemon worker is process-wide, but endpoints, credential ownership, and
//! workflow configuration belong to the plan owner's live session. This
//! factory is therefore invoked for each session (and again on config
//! replacement) and registers each adapter under its exact target id.

use std::sync::Arc;

use base64::Engine as _;
use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageGenerationConfig, ImageGenerationTarget,
    ImageTargetIdentity, WorkflowValueType,
};
use reqwest::header::{AUTHORIZATION, HeaderMap};
use sha2::{Digest as _, Sha256};

use crate::image_generation::adapters::comfyui::{
    ComfyuiHttpTransport, ComfyuiImagesAdapter, ComfyuiImagesAttemptInput,
    ComfyuiImagesPlanResolution, ComfyuiImagesPlanSource, comfyui_adapter_sealed,
};
use crate::image_generation::adapters::gemini::{
    GeminiImagesAdapter, GeminiImagesAttemptInput, GeminiImagesHttpTransport,
    GeminiImagesPlanResolution, GeminiImagesPlanSource, gemini_adapter_sealed,
};
use crate::image_generation::adapters::openrouter::{
    InputReferenceImageUrl, InputReferenceWire, OpenrouterImageRequest, OpenrouterImagesAdapter,
    OpenrouterImagesAttemptInput, OpenrouterImagesHttpTransport, OpenrouterImagesPlanResolution,
    OpenrouterImagesPlanSource, openrouter_adapter_sealed,
};
use crate::image_generation_comfyui::{
    BindingApplication, BoundWorkflowGraph, CanonicalBindingValue, clone_and_bind_workflow,
};
use crate::image_generation_job::{
    ImageGenerationAdapterMap, ImageGenerationHandoffRequest,
    read_image_generation_handoff_references, resolve_image_generation_handoff_target,
};
use crate::image_generation_runtime::{ImageRuntimeRegistry, TokioDnsResolver};
use crate::openai_images_adapter::{
    DecodeLimit, OpenaiImagesAdapter, OpenaiImagesHttpTransport, OpenaiImagesPlanResolution,
    OpenaiImagesPlanSource, PreflightInput, PreflightReference, openai_images_adapter_sealed,
    preflight,
};

const OPENAI_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const GEMINI_RESPONSE_BYTES: usize =
    crate::image_generation::adapters::gemini::MAX_INTERACTIONS_RESPONSE_BYTES;
const OPENROUTER_RESPONSE_BYTES: usize =
    crate::image_generation::adapters::openrouter::MAX_SUBMIT_RESPONSE_BYTES;

/// Build all configured direct-provider adapters for one live session. Failure
/// is intentionally all-or-nothing: retaining an old transport after a config
/// or credential change could send an approved plan to the wrong destination.
pub(crate) fn configured_image_generation_adapters(
    db: cockpit_db::Db,
    storage: Arc<crate::media_storage::MediaStorageRecovery>,
    runtime: Arc<ImageRuntimeRegistry>,
    config: &ImageGenerationConfig,
) -> anyhow::Result<ImageGenerationAdapterMap> {
    let mut adapters = ImageGenerationAdapterMap::new();
    for target in config.targets().iter().filter(|target| target.enabled) {
        let endpoint = config
            .endpoints()
            .iter()
            .find(|endpoint| endpoint.id == target.endpoint_id && endpoint.enabled)
            .ok_or_else(|| anyhow::anyhow!("configured image target endpoint is unavailable"))?
            .clone();
        let headers = runtime
            .resolve_ephemeral_headers(&endpoint)
            .map_err(anyhow::Error::from)?;
        let adapter_kind = endpoint.adapter;
        let adapter: Arc<dyn crate::image_generation_job::ImageGenerationAdapter> =
            match adapter_kind {
                ImageAdapterKind::OpenaiImages => Arc::new(OpenaiImagesAdapter::new(
                    Arc::new(OpenaiImagesHttpTransport::vetted(
                        &endpoint.origin,
                        bearer_token(&headers)?,
                        Arc::new(TokioDnsResolver),
                        OPENAI_RESPONSE_BYTES,
                    )?),
                    Arc::new(OpenaiPlanSource {
                        db: db.clone(),
                        storage: storage.clone(),
                        target: target.clone(),
                    }),
                    DecodeLimit::canonical(),
                )),
                ImageAdapterKind::OpenrouterImages => Arc::new(OpenrouterImagesAdapter::new(
                    Arc::new(OpenrouterImagesHttpTransport::vetted(
                        &endpoint.origin,
                        bearer_token(&headers)?,
                        Arc::new(TokioDnsResolver),
                        OPENROUTER_RESPONSE_BYTES,
                    )?),
                    Arc::new(OpenrouterPlanSource {
                        db: db.clone(),
                        storage: storage.clone(),
                        target: target.clone(),
                        endpoint,
                        headers: header_pairs(&headers),
                    }),
                )),
                ImageAdapterKind::GeminiImages => Arc::new(GeminiImagesAdapter::new(
                    Arc::new(GeminiImagesHttpTransport::vetted(
                        &endpoint.origin,
                        api_key(&headers)?,
                        Arc::new(TokioDnsResolver),
                        GEMINI_RESPONSE_BYTES,
                    )?),
                    Arc::new(GeminiPlanSource {
                        db: db.clone(),
                        storage: storage.clone(),
                        target: target.clone(),
                    }),
                )),
                ImageAdapterKind::Comfyui => {
                    let workflow_id = match &target.identity {
                        ImageTargetIdentity::Workflow { workflow_id, .. } => workflow_id,
                        _ => anyhow::bail!("ComfyUI target is missing a registered workflow"),
                    };
                    let workflow = config
                        .workflows()
                        .iter()
                        .find(|workflow| workflow.id == *workflow_id)
                        .ok_or_else(|| anyhow::anyhow!("ComfyUI workflow is unavailable"))?
                        .clone();
                    Arc::new(ComfyuiImagesAdapter::new(
                        Arc::new(ComfyuiHttpTransport::vetted(
                            &endpoint.origin,
                            endpoint.path_prefix.as_deref(),
                            endpoint.location,
                            Arc::new(TokioDnsResolver),
                            header_pairs(&headers),
                        )?),
                        Arc::new(ComfyPlanSource {
                            db: db.clone(),
                            storage: storage.clone(),
                            target: target.clone(),
                            workflow,
                            normalized_config_digest: normalized_target_config_digest(
                                config, &target.id,
                            )?,
                        }),
                    ))
                }
            };
        adapters.insert_target(adapter_kind, target.id.clone(), adapter);
    }
    Ok(adapters)
}

fn bearer_token(headers: &HeaderMap) -> anyhow::Result<&str> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("image endpoint bearer credential is unavailable"))?;
    authorization
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("image endpoint credential is not a bearer token"))
}

fn api_key(headers: &HeaderMap) -> anyhow::Result<&str> {
    let value = headers
        .get("x-goog-api-key")
        .or_else(|| headers.get(AUTHORIZATION))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Gemini image endpoint credential is unavailable"))?;
    Ok(value.strip_prefix("Bearer ").unwrap_or(value))
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_owned()))
        })
        .collect()
}

struct OpenaiPlanSource {
    db: cockpit_db::Db,
    storage: Arc<crate::media_storage::MediaStorageRecovery>,
    target: ImageGenerationTarget,
}
impl openai_images_adapter_sealed::Sealed for OpenaiPlanSource {}
#[async_trait::async_trait]
impl OpenaiImagesPlanSource for OpenaiPlanSource {
    async fn resolve(&self, request: &ImageGenerationHandoffRequest) -> OpenaiImagesPlanResolution {
        let resolved = match resolve_image_generation_handoff_target(&self.db, request).await {
            Ok(value) => value,
            Err(_) => {
                return OpenaiImagesPlanResolution::Unresolvable {
                    safe_reason: "sealed attempt unavailable".into(),
                };
            }
        };
        if resolved.target.target_id != self.target.id {
            return OpenaiImagesPlanResolution::Unresolvable {
                safe_reason: "target changed".into(),
            };
        }
        let model = match &self.target.identity {
            ImageTargetIdentity::HostedModel { model } => model.clone(),
            _ => {
                return OpenaiImagesPlanResolution::Unresolvable {
                    safe_reason: "target does not name an OpenAI model".into(),
                };
            }
        };
        let bytes = match read_image_generation_handoff_references(
            &self.db,
            &self.storage,
            &resolved.target,
            request.now_unix_ms,
        )
        .await
        {
            Ok(value) => value,
            Err(_) => {
                return OpenaiImagesPlanResolution::Unresolvable {
                    safe_reason: "reference media unavailable".into(),
                };
            }
        };
        let references = bytes
            .into_iter()
            .enumerate()
            .map(|(index, (mime, bytes))| PreflightReference {
                filename: format!("reference-{}", index + 1),
                mime,
                byte_length: bytes.len() as u64,
                bytes,
            })
            .collect::<Vec<_>>();
        let input = PreflightInput {
            model,
            prompt: request.sealed_prompt.payload.clone(),
            n: 1,
            width: resolved.target.resolved.width,
            height: resolved.target.resolved.height,
            quality: text_parameter(&resolved.target, "quality", "auto"),
            background: "auto".into(),
            output_format: resolved.target.resolved.format.clone(),
            moderation: "auto".into(),
            compression: integer_parameter(&resolved.target, "compression")
                .and_then(|value| u8::try_from(value).ok()),
            input_fidelity: text_parameter_optional(&resolved.target, "input_fidelity"),
        };
        match preflight(&input, &references) {
            Ok(plan) => OpenaiImagesPlanResolution::Resolved(Box::new(plan)),
            Err(_) => OpenaiImagesPlanResolution::Unresolvable {
                safe_reason: "sealed attempt is incompatible with the configured model".into(),
            },
        }
    }
}

struct GeminiPlanSource {
    db: cockpit_db::Db,
    storage: Arc<crate::media_storage::MediaStorageRecovery>,
    target: ImageGenerationTarget,
}
impl gemini_adapter_sealed::Sealed for GeminiPlanSource {}
#[async_trait::async_trait]
impl GeminiImagesPlanSource for GeminiPlanSource {
    async fn resolve(&self, request: &ImageGenerationHandoffRequest) -> GeminiImagesPlanResolution {
        let resolved = match resolve_image_generation_handoff_target(&self.db, request).await {
            Ok(value) => value,
            Err(_) => {
                return GeminiImagesPlanResolution::Unresolvable {
                    safe_reason: "sealed attempt unavailable".into(),
                };
            }
        };
        let model = match &self.target.identity {
            ImageTargetIdentity::HostedModel { model }
                if resolved.target.target_id == self.target.id =>
            {
                model.clone()
            }
            _ => {
                return GeminiImagesPlanResolution::Unresolvable {
                    safe_reason: "target changed".into(),
                };
            }
        };
        let references = match read_image_generation_handoff_references(
            &self.db,
            &self.storage,
            &resolved.target,
            request.now_unix_ms,
        )
        .await
        {
            Ok(value) => value
                .into_iter()
                .enumerate()
                .map(|(order, (mime_type, bytes))| {
                    crate::image_generation_runtime::gemini::GeminiReferenceAttachment {
                        mime_type,
                        bytes,
                        order: order as u32,
                    }
                })
                .collect(),
            Err(_) => {
                return GeminiImagesPlanResolution::Unresolvable {
                    safe_reason: "reference media unavailable".into(),
                };
            }
        };
        GeminiImagesPlanResolution::Resolved(Box::new(GeminiImagesAttemptInput {
            request: crate::image_generation_runtime::gemini::GeminiInteractionsRequestInput {
                model,
                prompt: request.sealed_prompt.payload.clone(),
                references,
                mime_type: Some(resolved.target.resolved.mime),
                aspect_ratio: None,
                image_size: None,
                planned_outputs: 1,
            },
        }))
    }
}

struct OpenrouterPlanSource {
    db: cockpit_db::Db,
    storage: Arc<crate::media_storage::MediaStorageRecovery>,
    target: ImageGenerationTarget,
    endpoint: ImageEndpoint,
    headers: Vec<(String, String)>,
}
impl openrouter_adapter_sealed::Sealed for OpenrouterPlanSource {}
#[async_trait::async_trait]
impl OpenrouterImagesPlanSource for OpenrouterPlanSource {
    async fn resolve(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> OpenrouterImagesPlanResolution {
        let resolved = match resolve_image_generation_handoff_target(&self.db, request).await {
            Ok(value) => value,
            Err(_) => {
                return OpenrouterImagesPlanResolution::Unresolvable {
                    safe_reason: "sealed attempt unavailable".into(),
                };
            }
        };
        let model = match &self.target.identity {
            ImageTargetIdentity::HostedModel { model }
                if resolved.target.target_id == self.target.id =>
            {
                model.clone()
            }
            _ => {
                return OpenrouterImagesPlanResolution::Unresolvable {
                    safe_reason: "target changed".into(),
                };
            }
        };
        let references = match read_image_generation_handoff_references(
            &self.db,
            &self.storage,
            &resolved.target,
            request.now_unix_ms,
        )
        .await
        {
            Ok(value) => value
                .into_iter()
                .map(|(mime, bytes)| InputReferenceWire {
                    kind: "image_url".into(),
                    image_url: InputReferenceImageUrl {
                        url: format!(
                            "data:{mime};base64,{}",
                            base64::engine::general_purpose::STANDARD.encode(bytes)
                        ),
                    },
                })
                .collect(),
            Err(_) => {
                return OpenrouterImagesPlanResolution::Unresolvable {
                    safe_reason: "reference media unavailable".into(),
                };
            }
        };
        OpenrouterImagesPlanResolution::Resolved(Box::new(OpenrouterImagesAttemptInput {
            origin: self.endpoint.origin.clone(),
            apply_openrouter_attribution: true,
            request: OpenrouterImageRequest {
                model,
                prompt: request.sealed_prompt.payload.clone(),
                resolution: None,
                aspect_ratio: None,
                size: Some(format!(
                    "{}x{}",
                    resolved.target.resolved.width, resolved.target.resolved.height
                )),
                quality: text_parameter_optional(&resolved.target, "quality"),
                output_format: Some(resolved.target.resolved.format.clone()),
                background: None,
                output_compression: integer_parameter(&resolved.target, "compression")
                    .and_then(|value| u32::try_from(value).ok()),
                seed: integer_parameter(&resolved.target, "seed"),
                n: 1,
                input_references: references,
                provider: None,
            },
            provider_headers: self.headers.clone(),
        }))
    }
}

struct ComfyPlanSource {
    db: cockpit_db::Db,
    storage: Arc<crate::media_storage::MediaStorageRecovery>,
    target: ImageGenerationTarget,
    workflow: cockpit_config::config::image_generation::RegisteredComfyWorkflow,
    normalized_config_digest: String,
}

impl ComfyPlanSource {
    /// Resolve an accepted provider operation only while the live adapter is
    /// still the exact immutable target sealed into the job. A target id may
    /// be reused after endpoint/workflow changes; sending an old prompt id to
    /// that replacement endpoint would cross authority boundaries.
    async fn accepted_operation_binding(
        &self,
        job_id: uuid::Uuid,
        slot_id: uuid::Uuid,
        attempt_number: u32,
        external_operation_id: uuid::Uuid,
    ) -> Option<(String, Vec<u8>)> {
        let target_id = self.target.id.clone();
        let normalized_config_digest = self.normalized_config_digest.clone();
        self.db
            .read(move |conn| {
                let (provider_operation_id, reconciliation_context, canonical, plan_digest): (
                    String,
                    Vec<u8>,
                    Vec<u8>,
                    String,
                ) = conn.query_row(
                    "SELECT b.provider_operation_id,b.reconciliation_context,p.canonical_plan,p.plan_digest \
                     FROM image_generation_provider_operation_bindings b \
                     JOIN image_generation_plans p ON p.job_id=b.job_id \
                     WHERE b.job_id=?1 AND b.slot_id=?2 AND b.attempt_number=?3 AND b.external_operation_id=?4",
                    rusqlite::params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number), external_operation_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                let plan = crate::image_generation_job::ImageGenerationPlanV1::from_canonical(
                    &canonical,
                    &plan_digest,
                )?;
                let sealed_target = plan
                    .targets
                    .iter()
                    .find(|target| {
                        target.target_id == target_id
                            && target.slots.iter().any(|slot| slot.slot_id == slot_id)
                    })
                    .ok_or_else(|| anyhow::anyhow!("accepted provider operation target is absent"))?;
                anyhow::ensure!(
                    sealed_target.normalized_config_digest == normalized_config_digest
                        && sealed_target.destination.adapter_kind == "comfyui",
                    "accepted provider operation target changed"
                );
                Ok((provider_operation_id, reconciliation_context))
            })
            .await
            .ok()
    }
}
impl comfyui_adapter_sealed::Sealed for ComfyPlanSource {}
#[async_trait::async_trait]
impl ComfyuiImagesPlanSource for ComfyPlanSource {
    async fn resolve_handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ComfyuiImagesPlanResolution {
        let resolved = match resolve_image_generation_handoff_target(&self.db, request).await {
            Ok(value) if value.target.target_id == self.target.id => value,
            _ => {
                return ComfyuiImagesPlanResolution::Unresolvable {
                    safe_reason: "sealed workflow attempt is unavailable".into(),
                };
            }
        };
        let references = match read_image_generation_handoff_references(
            &self.db,
            &self.storage,
            &resolved.target,
            request.now_unix_ms,
        )
        .await
        {
            Ok(references) => references,
            Err(_) => {
                return ComfyuiImagesPlanResolution::Unresolvable {
                    safe_reason: "reference media unavailable".into(),
                };
            }
        };
        let mut references = references.into_iter();
        let mut uploads = Vec::new();
        let mut applications = Vec::new();
        for binding in &self.workflow.bindings {
            if binding.value_type == WorkflowValueType::Image {
                if let Some((mime, bytes)) = references.next() {
                    let index = uploads.len() + 1;
                    let placeholder = format!(
                        "cockpit-reference-{}-{index}",
                        request.external_operation_id.simple()
                    );
                    let extension = match comfyui_upload_extension(&mime) {
                        Some(extension) => extension,
                        None => {
                            return ComfyuiImagesPlanResolution::Unresolvable {
                                safe_reason:
                                    "reference media type is unsupported by ComfyUI upload".into(),
                            };
                        }
                    };
                    uploads.push(
                        crate::image_generation::adapters::comfyui::ComfyuiUploadInput {
                            placeholder: placeholder.clone(),
                            artifact_name: format!("reference-{index}.{extension}"),
                            mime,
                            bytes,
                        },
                    );
                    applications.push(BindingApplication {
                        parameter: binding.parameter,
                        value: CanonicalBindingValue::ImageReference {
                            upload_name: placeholder,
                        },
                    });
                }
                continue;
            }
            let key = match serde_json::to_value(binding.parameter)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
            {
                Some(key) => key,
                None => {
                    return ComfyuiImagesPlanResolution::Unresolvable {
                        safe_reason: "configured workflow binding is invalid".into(),
                    };
                }
            };
            let Some(parameter) = resolved.target.typed_parameters.get(&key) else {
                continue;
            };
            let value = match parameter {
                crate::image_generation_job::TypedParameterV1::Integer(value) => {
                    CanonicalBindingValue::Integer(*value)
                }
                crate::image_generation_job::TypedParameterV1::Text(value) => {
                    CanonicalBindingValue::Text(value.clone())
                }
                crate::image_generation_job::TypedParameterV1::Boolean(_) => {
                    return ComfyuiImagesPlanResolution::Unresolvable {
                        safe_reason: "configured workflow binding has an incompatible value".into(),
                    };
                }
            };
            applications.push(BindingApplication {
                parameter: binding.parameter,
                value,
            });
        }
        if references.next().is_some() {
            return ComfyuiImagesPlanResolution::Unresolvable {
                safe_reason: "configured workflow has no binding for every reference".into(),
            };
        }
        let BoundWorkflowGraph { graph_json, .. } =
            match clone_and_bind_workflow(&self.workflow, &applications) {
                Ok(value) => value,
                Err(_) => {
                    return ComfyuiImagesPlanResolution::Unresolvable {
                        safe_reason: "configured workflow is invalid".into(),
                    };
                }
            };
        match serde_json::from_str(&graph_json) {
            Ok(prompt_graph) => {
                ComfyuiImagesPlanResolution::Resolved(Box::new(ComfyuiImagesAttemptInput {
                    prompt_graph,
                    client_id: request.external_operation_id.to_string(),
                    uploads,
                    declared_outputs: self.workflow.outputs.clone(),
                }))
            }
            Err(_) => ComfyuiImagesPlanResolution::Unresolvable {
                safe_reason: "configured workflow is invalid".into(),
            },
        }
    }
    async fn resolve_reconcile(
        &self,
        request: &crate::image_generation_job::ImageGenerationReconcileRequest,
    ) -> Option<crate::image_generation::adapters::comfyui::ComfyuiReconcileInput> {
        let job_id = request.job_id;
        let slot_id = request.slot_id;
        let attempt_number = request.attempt_number;
        let operation_id = request.external_operation_id;
        let (prompt_id, reconciliation_context) = self
            .accepted_operation_binding(job_id, slot_id, attempt_number, operation_id)
            .await?;
        let declared_outputs = serde_json::from_slice(&reconciliation_context).ok()?;
        Some(
            crate::image_generation::adapters::comfyui::ComfyuiReconcileInput {
                prompt_id,
                declared_outputs,
            },
        )
    }
    async fn resolve_cancel(
        &self,
        request: &crate::image_generation_job::ImageGenerationCancelRequest,
    ) -> Option<crate::image_generation::adapters::comfyui::ComfyuiCancelInput> {
        let job_id = request.job_id;
        let slot_id = request.slot_id;
        let attempt_number = request.attempt_number;
        let operation_id = request.external_operation_id;
        let (prompt_id, _) = self
            .accepted_operation_binding(job_id, slot_id, attempt_number, operation_id)
            .await?;
        Some(
            crate::image_generation::adapters::comfyui::ComfyuiCancelInput {
                capability:
                    crate::image_generation_comfyui::ComfyCancellationCapability::QueuedPromptDelete,
                prompt_id: Some(prompt_id),
                job_id: None,
            },
        )
    }
}

fn text_parameter_optional(
    target: &crate::image_generation_job::TargetPlanV1,
    key: &str,
) -> Option<String> {
    match target.typed_parameters.get(key) {
        Some(crate::image_generation_job::TypedParameterV1::Text(value)) => Some(value.clone()),
        _ => None,
    }
}
fn text_parameter(
    target: &crate::image_generation_job::TargetPlanV1,
    key: &str,
    default: &str,
) -> String {
    text_parameter_optional(target, key).unwrap_or_else(|| default.into())
}
fn integer_parameter(target: &crate::image_generation_job::TargetPlanV1, key: &str) -> Option<i64> {
    match target.typed_parameters.get(key) {
        Some(crate::image_generation_job::TypedParameterV1::Integer(value)) => Some(*value),
        _ => None,
    }
}

fn comfyui_upload_extension(mime: &str) -> Option<&'static str> {
    match mime {
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        "image/webp" => Some("webp"),
        _ => None,
    }
}

fn normalized_target_config_digest(
    config: &ImageGenerationConfig,
    target_id: &str,
) -> anyhow::Result<String> {
    let identity = config.target_immutable_identity(target_id)?;
    let mut digest = Sha256::new();
    digest.update((identity.len() as u64).to_be_bytes());
    digest.update(identity.as_bytes());
    Ok(crate::intel::hex_lower(&digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::comfyui_upload_extension;

    #[test]
    fn comfyui_reference_upload_mime_allowlist_fails_closed() {
        assert_eq!(comfyui_upload_extension("image/png"), Some("png"));
        assert_eq!(comfyui_upload_extension("image/jpeg"), Some("jpg"));
        assert_eq!(comfyui_upload_extension("image/webp"), Some("webp"));
        assert_eq!(comfyui_upload_extension("image/svg+xml"), None);
        assert_eq!(comfyui_upload_extension("application/octet-stream"), None);
    }
}
