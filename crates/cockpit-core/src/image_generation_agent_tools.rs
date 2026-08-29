//! Image-generation agent tools and composite authorization.
//!
//! This module exposes four strict canonical built-in tool schemas
//! (`list_image_generation_targets`, `generate_image`,
//! `get_image_generation_job`, `cancel_image_generation_job`) and the
//! one immutable composite authorization decision that covers
//! destinations, reference egress, fanout, spend risk, and normal
//! filesystem authority.
//!
//! The module is UI-free and transport-free. It produces typed,
//! bounded, denial-by-default structures. The job/spend foundations
//! (`crate::image_generation_job` and the `cockpit-db` image-spend ledger),
//! the canonical
//! dispatch (`crate::engine`), and the central authorization chokepoint
//! are reused — this layer only adds the agent-facing tool surface and
//! the composite decision that binds them.
//!
//! Design invariants (prompt
//! `image-generation-agent-tools-and-authorization`):
//!
//! - Discovery never grants generation authority.
//! - There is no global/unscoped image egress or output grant.
//! - Reference egress grants have only `once`, `session`, and
//!   machine-local `project` scopes.
//! - A grant tuple binds provider, model, endpoint origin, connected
//!   location class, credential identity, target/workflow digest,
//!   reference-egress boolean, maximum fanout, maximum total outputs,
//!   and maximum known cost micros or explicit `unknown_cost_allowed`.
//!   It never contains a wildcard destination or unbounded implicit
//!   maximum.
//! - Yolo opens no human prompt and records disposition
//!   `agent_discretion` — never `allow_once` and never a persisted
//!   grant — after every hard gate passes.
//! - Unknown maximum may dispatch only when request, session, and
//!   project spend choices are all explicitly Unlimited.
//! - The user-confirmed known-cost base-tier threshold is USD 0.25
//!   (250_000 USD micros), configurable from zero through the
//!   documented hard ceiling.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

pub const BASE_TIER_KNOWN_COST_THRESHOLD_USD_MICROS: u64 = 250_000;
pub const BASE_TIER_KNOWN_COST_HARD_CEILING_USD_MICROS: u64 = 10_000_000;
pub const MAX_GENERATE_IMAGE_TARGETS: usize = 16;
pub const MAX_GENERATE_IMAGE_SAMPLES_PER_TARGET: u32 = 64;
pub const MAX_GENERATE_IMAGE_TOTAL_OUTPUTS: u32 = 256;
pub const MAX_GENERATE_IMAGE_DIMENSION: u32 = 16_384;
pub const MAX_GENERATE_IMAGE_REFERENCES: usize = 64;
pub const MAX_GENERATE_IMAGE_TYPED_PARAMETERS: usize = 64;
pub const MAX_GENERATE_IMAGE_PROMPT_BYTES: usize = 8_192;
pub const MAX_GENERATE_IMAGE_STRING_BYTES: usize = 1_024;

/// The four canonical image-generation agent tool names, in the order
/// the tool descriptions instruct discovery first.
pub const IMAGE_GENERATION_TOOL_NAMES: [&str; 4] = [
    "list_image_generation_targets",
    "generate_image",
    "get_image_generation_job",
    "cancel_image_generation_job",
];

/// Typed reference tag: either an uploaded `attachment_id` or a
/// daemon-local `local_path`. Raw URLs and provider JSON are rejected
/// at the schema layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageReferenceTag {
    Attachment { attachment_id: String },
    LocalPath { local_path: String },
}

/// Typed per-target override entry inside `generate_image`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerateImageTargetEntry {
    pub target_id: String,
    #[serde(default = "default_one_sample")]
    pub samples: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, TypedParameter>,
}

fn default_one_sample() -> u32 {
    1
}

/// Typed parameter value (boolean, integer, or text). Unknown types
/// are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TypedParameter {
    Boolean(bool),
    Integer(i64),
    Text(String),
}

/// Spend policy choice for request, session, and project scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendPolicyChoice {
    Unlimited,
    Finite { usd_micros: u64 },
}

/// Connected location class (mirrors config, kept local to avoid an
/// upward config dependency in this pure layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationClass {
    Local,
    PrivateNetwork,
    PublicCloud,
}

impl LocationClass {
    /// Stable lowercase label used in model-facing discovery copy.
    pub fn label(self) -> &'static str {
        match self {
            LocationClass::Local => "local",
            LocationClass::PrivateNetwork => "private_network",
            LocationClass::PublicCloud => "public_cloud",
        }
    }
}

/// Risk tier for a generate-image request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerateImageRiskTier {
    /// One target, one output, known cost at or below the base threshold.
    Base,
    /// Fanout, multiple outputs, cost above threshold, unknown cost, or
    /// reference egress to a destination without a matching grant.
    Elevated,
}

/// The immutable plan projection displayed for approval. It is
/// review-only and cannot edit the plan. Every authority-affecting
/// mutation produces a new digest; display rename alone does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageGenerationPlanProjection {
    pub destinations: Vec<ProjectionDestination>,
    pub prompt_collapsed: bool,
    /// SHA-256 of the protected prompt payload. It binds human approval without
    /// exposing text to the projection, interrupt, audit, or status surfaces.
    pub prompt_digest: String,
    pub references: Vec<ProjectionReference>,
    pub target_requests: Vec<ProjectionTargetRequest>,
    pub sizes: Vec<ProjectionSize>,
    pub formats: Vec<String>,
    pub parameters: BTreeMap<String, TypedParameter>,
    pub fanout: u32,
    pub total_outputs: u32,
    pub cost_maximum: Option<u64>,
    pub budget_disposition: BudgetDisposition,
    pub output_directory: String,
    pub output_base_stem: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionTargetRequest {
    pub target_id: String,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub samples: u32,
    pub parameters: BTreeMap<String, TypedParameter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionDestination {
    pub target_id: String,
    pub location_class: LocationClass,
    pub adapter_kind: String,
}

/// Safe, redacted, model-facing projection of one image-generation target for
/// discovery (`list_image_generation_targets`). Mirrors the redaction contract
/// of [`ProjectionDestination`] and the `generate_image`/`get_image_generation_job`
/// outcomes: it carries only non-identifying facts — the target id, adapter
/// kind, connected location class, enabled flag, health state code, and (when a
/// capability snapshot backs it) the supported formats, maximum dimensions,
/// and allowed parameter names plus a freshness flag. It NEVER carries the
/// endpoint id/origin, connected IPs, credential identity digest, target
/// immutable identity, model/workflow digest, raw workflow JSON, or headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageGenerationTargetProjection {
    pub target_id: String,
    pub adapter_kind: String,
    pub location_class: LocationClass,
    pub enabled: bool,
    pub health_state: String,
    pub supported_formats: Vec<String>,
    pub maximum_width: Option<u32>,
    pub maximum_height: Option<u32>,
    pub allowed_parameters: Vec<String>,
    /// `true` when a dispatchable capability snapshot backs this projection.
    pub capability_fresh: bool,
}

/// Outcome of session-scoped image-generation target discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationTargetDiscovery {
    /// Dispatch is latched unavailable after a failed configuration reconcile.
    /// Discovery is withheld even when a prior registry pair remains installed.
    DispatchUnavailable,
    /// Redacted target projections. An empty vector means no targets are configured.
    Targets(Vec<ImageGenerationTargetProjection>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionReference {
    /// Secret-free stable identity binding. It is derived from the attachment
    /// identity/checksum by the dispatch service and is never a local path,
    /// URL, or provider payload.
    pub identity_digest: String,
    pub thumbnail: bool,
    /// The exact target this reference may egress to. This association is part
    /// of the immutable approval digest; moving a reference to another target
    /// cannot reuse an approval grant.
    pub destination_target_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionSize {
    pub target_id: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDisposition {
    WithinBudget,
    Exhausted,
    UnknownCostBlocked,
    UnknownCostAllowed,
}

/// Return the strict JSON schema for one of the four canonical
/// image-generation agent tools. Returns `Value::Null` for an unknown
/// name.
pub fn image_generation_tool_schema(name: &str) -> Value {
    match name {
        "list_image_generation_targets" => list_image_generation_targets_schema(),
        "generate_image" => generate_image_schema(),
        "get_image_generation_job" => get_image_generation_job_schema(),
        "cancel_image_generation_job" => cancel_image_generation_job_schema(),
        _ => Value::Null,
    }
}

fn list_image_generation_targets_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "x-cockpit-primary-field": "include_disabled",
        "properties": {
            "include_disabled": {
                "type": "boolean",
                "default": false,
                "description": "When true, include disabled targets in the listing (default false: only enabled targets are returned)."
            }
        },
        "additionalProperties": false
    })
}

fn generate_image_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "x-cockpit-primary-field": "prompt",
        "properties": {
            "prompt": {
                "type": "string",
                "x-cockpit-kind": "prompt",
                "description": "The text prompt for image generation. Required."
            },
            "targets": {
                "type": "array",
                "maxItems": MAX_GENERATE_IMAGE_TARGETS,
                "description": "Optional per-target entries. Omitted means the configured default target with one sample. Duplicate target_id values are rejected.",
                "items": {
                    "type": "object",
                    "x-cockpit-primary-field": "target_id",
                    "properties": {
                        "target_id": { "type": "string", "description": "The target identifier to use." },
                        "samples": { "type": "integer", "minimum": 1, "maximum": MAX_GENERATE_IMAGE_SAMPLES_PER_TARGET, "default": 1, "description": "Number of samples for this target (default 1, capped)." },
                        "width": { "type": "integer", "minimum": 1, "maximum": MAX_GENERATE_IMAGE_DIMENSION, "description": "Optional requested width in pixels." },
                        "height": { "type": "integer", "minimum": 1, "maximum": MAX_GENERATE_IMAGE_DIMENSION, "description": "Optional requested height in pixels." },
                        "format": { "type": "string", "enum": ["png", "jpeg", "webp", "svg"], "description": "Optional output format." },
                        "parameters": {
                            "type": "object",
                            "description": "Optional typed target parameters, keyed by parameter name.",
                            "maxProperties": MAX_GENERATE_IMAGE_TYPED_PARAMETERS,
                            "propertyNames": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": MAX_GENERATE_IMAGE_STRING_BYTES
                            },
                            "additionalProperties": {
                                "oneOf": [
                                    {
                                        "type": "object",
                                        "properties": {
                                            "type": { "const": "boolean" },
                                            "value": { "type": "boolean" }
                                        },
                                        "required": ["type", "value"],
                                        "additionalProperties": false
                                    },
                                    {
                                        "type": "object",
                                        "properties": {
                                            "type": { "const": "integer" },
                                            "value": {
                                                "type": "integer",
                                                "minimum": i64::MIN,
                                                "maximum": i64::MAX
                                            }
                                        },
                                        "required": ["type", "value"],
                                        "additionalProperties": false
                                    },
                                    {
                                        "type": "object",
                                        "properties": {
                                            "type": { "const": "text" },
                                            "value": { "type": "string", "maxLength": MAX_GENERATE_IMAGE_STRING_BYTES }
                                        },
                                        "required": ["type", "value"],
                                        "additionalProperties": false
                                    }
                                ]
                            }
                        }
                    },
                    "required": ["target_id"],
                    "additionalProperties": false
                }
            },
            "width": { "type": "integer", "minimum": 1, "maximum": MAX_GENERATE_IMAGE_DIMENSION, "description": "Optional shared requested width applied to all targets." },
            "height": { "type": "integer", "minimum": 1, "maximum": MAX_GENERATE_IMAGE_DIMENSION, "description": "Optional shared requested height applied to all targets." },
            "format": { "type": "string", "enum": ["png", "jpeg", "webp", "svg"], "description": "Optional shared output format applied to all targets." },
            "references": {
                "type": "array",
                "maxItems": MAX_GENERATE_IMAGE_REFERENCES,
                "description": "Optional references tagged as attachment_id or local_path. Raw URLs and provider JSON are rejected.",
                "items": {
                    "type": "object",
                    "properties": {
                        "attachment_id": { "type": "string", "description": "An uploaded attachment identifier." },
                        "local_path": { "type": "string", "x-cockpit-kind": "path", "description": "A daemon-local path; first passes normal read-path authorization and is normalized once into a typed attachment." }
                    },
                    "additionalProperties": false
                }
            },
            "directory": { "type": "string", "x-cockpit-kind": "path", "description": "Required output directory; uses normal current write-path authority and exclusive publication." },
            "base_stem": { "type": "string", "description": "Required output base stem for published artifact names." }
        },
        "required": ["prompt", "directory", "base_stem"],
        "additionalProperties": false
    })
}

fn get_image_generation_job_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "x-cockpit-primary-field": "job_id",
        "properties": {
            "job_id": { "type": "string", "description": "The durable job identifier to fetch session-authorized status for." }
        },
        "required": ["job_id"],
        "additionalProperties": false
    })
}

fn cancel_image_generation_job_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "x-cockpit-primary-field": "job_id",
        "properties": {
            "job_id": { "type": "string", "description": "The durable job identifier to request idempotent cancellation for. The current session must control the job." }
        },
        "required": ["job_id"],
        "additionalProperties": false
    })
}

/// Validate a `generate_image` argument value against the strict rules
/// before any plan is formed. Returns `Ok(())` when the arguments are
/// structurally valid, or an error describing the first violation.
///
/// This is the schema-layer guard: it rejects raw URLs, provider JSON,
/// workflow data, duplicate targets, and unknown fields. It does not
/// perform authorization — that is the central chokepoint
/// `Approver::authorize(AuthorizationRequest::ImageGeneration { .. })`.
pub fn validate_generate_image_args(args: &Value) -> Result<()> {
    let obj = args
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("generate_image arguments must be an object"))?;
    ensure_only_keys(
        obj,
        &[
            "prompt",
            "targets",
            "width",
            "height",
            "format",
            "references",
            "directory",
            "base_stem",
        ],
        "generate_image arguments",
    )?;

    let prompt = obj
        .get("prompt")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("generate_image requires a string `prompt`"))?;
    ensure!(
        !prompt.trim().is_empty(),
        "generate_image `prompt` must not be empty"
    );
    ensure!(
        prompt.len() <= MAX_GENERATE_IMAGE_PROMPT_BYTES,
        "generate_image `prompt` exceeds the {} byte cap",
        MAX_GENERATE_IMAGE_PROMPT_BYTES
    );

    obj.get("directory")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("generate_image requires a `directory`"))?;
    let base_stem = obj
        .get("base_stem")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("generate_image requires a `base_stem`"))?;
    ensure!(
        !base_stem.is_empty() && base_stem.len() <= MAX_GENERATE_IMAGE_STRING_BYTES,
        "generate_image `base_stem` is outside its bound"
    );
    ensure!(
        is_safe_filename_component(base_stem),
        "generate_image `base_stem` must be a single path component"
    );

    let mut total_outputs: u32 = 0;
    let mut seen_targets = std::collections::BTreeSet::new();
    if let Some(targets_value) = obj.get("targets") {
        let targets = targets_value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("generate_image `targets` must be an array"))?;
        ensure!(
            targets.len() <= MAX_GENERATE_IMAGE_TARGETS,
            "generate_image `targets` exceeds the {} target cap",
            MAX_GENERATE_IMAGE_TARGETS
        );
        for entry in targets {
            let target_obj = entry
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("each target entry must be an object"))?;
            ensure_only_keys(
                target_obj,
                &[
                    "target_id",
                    "samples",
                    "width",
                    "height",
                    "format",
                    "parameters",
                ],
                "generate_image target",
            )?;
            let target_id = target_obj
                .get("target_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("each target entry requires a `target_id`"))?;
            ensure!(
                !seen_targets.contains(target_id),
                "generate_image `targets` contains a duplicate target_id `{target_id}`"
            );
            seen_targets.insert(target_id.to_string());
            let samples = match target_obj.get("samples") {
                Some(value) => u32::try_from(value.as_u64().ok_or_else(|| {
                    anyhow::anyhow!(
                        "generate_image target `{target_id}` samples must be an integer"
                    )
                })?)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "generate_image target `{target_id}` samples is outside the supported integer range"
                    )
                })?,
                None => 1,
            };
            ensure!(
                (1..=MAX_GENERATE_IMAGE_SAMPLES_PER_TARGET).contains(&samples),
                "generate_image target `{target_id}` samples outside 1..={}",
                MAX_GENERATE_IMAGE_SAMPLES_PER_TARGET
            );
            total_outputs = total_outputs
                .checked_add(samples)
                .ok_or_else(|| anyhow::anyhow!("generate_image total outputs overflow"))?;
            validate_optional_dimension(target_obj, "width", target_id)?;
            validate_optional_dimension(target_obj, "height", target_id)?;
            if let Some(format) = target_obj.get("format") {
                let fmt = format.as_str().ok_or_else(|| {
                    anyhow::anyhow!("generate_image target `{target_id}` `format` must be a string")
                })?;
                ensure!(
                    matches!(fmt, "png" | "jpeg" | "webp" | "svg"),
                    "generate_image target `{target_id}` has an unsupported format"
                );
            }
            validate_typed_parameters(target_obj.get("parameters"), target_id)?;
        }
    } else {
        total_outputs = 1;
    }
    ensure!(
        total_outputs <= MAX_GENERATE_IMAGE_TOTAL_OUTPUTS,
        "generate_image total outputs `{total_outputs}` exceeds the {} cap",
        MAX_GENERATE_IMAGE_TOTAL_OUTPUTS
    );

    validate_optional_dimension(obj, "width", "shared")?;
    validate_optional_dimension(obj, "height", "shared")?;
    if let Some(format) = obj.get("format") {
        let fmt = format
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("generate_image shared `format` must be a string"))?;
        ensure!(
            matches!(fmt, "png" | "jpeg" | "webp" | "svg"),
            "generate_image shared `format` is unsupported"
        );
    }

    if let Some(references_value) = obj.get("references") {
        let references = references_value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("generate_image `references` must be an array"))?;
        ensure!(
            references.len() <= MAX_GENERATE_IMAGE_REFERENCES,
            "generate_image `references` exceeds the {} cap",
            MAX_GENERATE_IMAGE_REFERENCES
        );
        for reference in references {
            let reference_obj = reference
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("each reference must be an object"))?;
            ensure_only_keys(
                reference_obj,
                &["attachment_id", "local_path"],
                "generate_image reference",
            )?;
            let has_attachment = reference_obj.contains_key("attachment_id");
            let has_local = reference_obj.contains_key("local_path");
            ensure!(
                has_attachment ^ has_local,
                "each reference must tag exactly one of `attachment_id` or `local_path`"
            );
            if has_local {
                let local_path = reference_obj
                    .get("local_path")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                ensure!(
                    !local_path.trim().is_empty(),
                    "a `local_path` reference must not be empty"
                );
                ensure!(
                    !looks_like_raw_url(local_path),
                    "raw URLs are not accepted as references; upload an attachment instead"
                );
            } else {
                let attachment_id = reference_obj
                    .get("attachment_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow::anyhow!("an `attachment_id` reference must be a string")
                    })?;
                ensure!(
                    !attachment_id.trim().is_empty(),
                    "an `attachment_id` reference must not be empty"
                );
            }
        }
    }

    Ok(())
}

fn ensure_only_keys(obj: &Map<String, Value>, allowed: &[&str], label: &str) -> Result<()> {
    if let Some(key) = obj.keys().find(|key| !allowed.contains(&key.as_str())) {
        anyhow::bail!("{label} contains unknown field `{key}`");
    }
    Ok(())
}

fn validate_optional_dimension(obj: &Map<String, Value>, key: &str, label: &str) -> Result<()> {
    if let Some(value) = obj.get(key) {
        let dim = value
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("generate_image {label} `{key}` must be an integer"))?;
        ensure!(
            dim >= 1 && dim <= MAX_GENERATE_IMAGE_DIMENSION as u64,
            "generate_image {label} `{key}` is outside 1..={}",
            MAX_GENERATE_IMAGE_DIMENSION
        );
    }
    Ok(())
}

fn validate_typed_parameters(parameters: Option<&Value>, target_id: &str) -> Result<()> {
    let Some(parameters) = parameters else {
        return Ok(());
    };
    let params = parameters.as_object().ok_or_else(|| {
        anyhow::anyhow!("generate_image target `{target_id}` parameters must be an object")
    })?;
    ensure!(
        params.len() <= MAX_GENERATE_IMAGE_TYPED_PARAMETERS,
        "generate_image target `{target_id}` parameters exceed the {} cap",
        MAX_GENERATE_IMAGE_TYPED_PARAMETERS
    );
    for (key, parameter) in params {
        ensure!(
            !key.is_empty() && key.len() <= MAX_GENERATE_IMAGE_STRING_BYTES,
            "generate_image target `{target_id}` parameter key is outside its bound"
        );
        let parameter = parameter.as_object().ok_or_else(|| {
            anyhow::anyhow!(
                "generate_image target `{target_id}` parameter `{key}` must be an object"
            )
        })?;
        ensure!(
            parameter.len() == 2
                && parameter.contains_key("type")
                && parameter.contains_key("value"),
            "generate_image target `{target_id}` parameter `{key}` must contain only `type` and `value`"
        );
        let kind = parameter
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "generate_image target `{target_id}` parameter `{key}` requires a `type`"
                )
            })?;
        ensure!(
            matches!(kind, "boolean" | "integer" | "text"),
            "generate_image target `{target_id}` parameter `{key}` has an unsupported type"
        );
        let value = parameter.get("value").ok_or_else(|| {
            anyhow::anyhow!(
                "generate_image target `{target_id}` parameter `{key}` requires a `value`"
            )
        })?;
        let valid = match kind {
            "boolean" => value.is_boolean(),
            "integer" => value.is_i64(),
            "text" => value
                .as_str()
                .is_some_and(|text| text.len() <= MAX_GENERATE_IMAGE_STRING_BYTES),
            _ => false,
        };
        ensure!(
            valid,
            "generate_image target `{target_id}` parameter `{key}` has a value incompatible with its type"
        );
        // Keep the schema-layer validator tied to the public typed wire
        // representation. This prevents a future schema/validator edit from
        // accepting a value that `BTreeMap<String, TypedParameter>` cannot
        // deserialize at the dispatch boundary.
        serde_json::from_value::<TypedParameter>(Value::Object(parameter.clone())).map_err(
            |err| {
                anyhow::anyhow!(
                    "generate_image target `{target_id}` parameter `{key}` is not a typed parameter: {err}"
                )
            },
        )?;
    }
    Ok(())
}

fn is_safe_filename_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_GENERATE_IMAGE_STRING_BYTES
        && s != "."
        && s != ".."
        && !s.contains(['/', '\\'])
        && !s.chars().any(char::is_control)
}

fn looks_like_raw_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
}

/// Compute the canonical serialized plan projection and its digest.
/// The projection is review-only and cannot edit the plan. Every
/// authority-affecting mutation changes the digest; display rename
/// alone does not.
/// The digest of an immutable image-generation plan projection, threaded into
/// [`crate::approval::AuthorizationRequest::ImageGeneration`] to identify the
/// exact plan under decision without carrying its prompt text or references.
///
/// The inner hex string is private and its ONLY production constructor is
/// [`plan_projection_digest`]: raw/attacker-controlled strings can never be
/// wrapped as a `PlanDigest` and reach the persisted interrupt-prompt sink
/// (`approval/policy.rs`), which reads only [`PlanDigest::as_str`]. This is the
/// type-safety half of the inc1-review hard constraint for real dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDigest(String);

impl PlanDigest {
    /// The lowercase-hex digest string, for display/prefixing at the authz
    /// boundary. Read-only: there is no public way to construct a `PlanDigest`
    /// from an arbitrary string in production.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only raw constructor. `#[cfg(test)]`-gated so production code cannot
    /// bypass [`plan_projection_digest`]; tests may synthesize a digest without
    /// assembling a full projection.
    #[cfg(test)]
    pub(crate) fn from_raw_for_test(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

pub fn plan_projection_digest(projection: &ImageGenerationPlanProjection) -> Result<PlanDigest> {
    let bytes = serde_json::to_vec(projection)?;
    ensure!(!bytes.is_empty(), "plan projection must not be empty");
    Ok(PlanDigest(hex_lower(&Sha256::digest(&bytes))))
}

/// Compute the risk tier for a generate-image request given the
/// resolved fanout, total outputs, cost maximum, and whether reference
/// egress to a destination lacks a matching grant.
pub fn classify_risk(
    fanout: u32,
    total_outputs: u32,
    cost_maximum: Option<u64>,
    reference_egress_unmatched: bool,
    base_threshold_usd_micros: u64,
) -> GenerateImageRiskTier {
    let single_target_single_output = fanout == 1 && total_outputs == 1;
    let known_within_base = cost_maximum
        .map(|cost| cost <= base_threshold_usd_micros)
        .unwrap_or(false);
    let unknown_cost = cost_maximum.is_none();
    if single_target_single_output
        && known_within_base
        && !reference_egress_unmatched
        && !unknown_cost
    {
        GenerateImageRiskTier::Base
    } else {
        GenerateImageRiskTier::Elevated
    }
}

// NOTE: the bespoke `authorize_generate_image` composite ladder
// (`AuthorizationInputs` + a local `ApprovalMode`/`ImageGenerationAuthorization`
// mirror) was DELETED. It had zero non-test callers and re-implemented a
// parallel ApprovalMode / hard-gate / grant-matching / risk ladder outside the
// central chokepoint. The single decision issuer is now
// `Approver::authorize(AuthorizationRequest::ImageGeneration { .. })`
// (`approval/policy.rs::approve_image_generation_inner`). The reusable pure
// risk classification stays here as [`classify_risk`] for tests and callers
// that need the tier; the Approver honors a matching grant without treating
// the classifier as a second decision issuer.

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Return the terse (Normal/Frontier) tool description for one of the four
/// canonical image-generation agent tools. Each stays within the terse
/// description budget and instructs discovery first; the fuller, more cautious
/// account of exact/nearest/provider-default dimensions, samples/caps,
/// reference egress, partial failure, cancellation, and no substitution lives
/// in [`image_generation_tool_verbose_description`].
pub fn image_generation_tool_description(name: &str) -> Option<&'static str> {
    Some(match name {
        "list_image_generation_targets" => {
            "List image-generation targets with capability, health, freshness, and cost projections. Disabled targets are hidden unless include_disabled is true. Call this first before generate_image. Returns no secrets, workflow, or authority."
        }
        "generate_image" => {
            "Submit an image-generation job from a prompt with per-target overrides, shared dimensions, and references. Partial failure keeps slots; cancellation is idempotent; no mid-job substitution."
        }
        "get_image_generation_job" => {
            "Return session-authorized durable status and safe result metadata for an image-generation job. Never reveals another session's prompt, references, cost, paths, destinations, or artifacts."
        }
        "cancel_image_generation_job" => {
            "Request idempotent cancellation for an image-generation job the current session may control. Successful slots remain published on partial failure."
        }
        _ => return None,
    })
}

/// Return the verbose Defensive-mode description for one of the four canonical
/// image-generation agent tools. Each is a longer, more cautious form of the
/// terse [`image_generation_tool_description`]: it adds explicit
/// when-to-use / when-not-to-use steering and spells out the read-only,
/// session-scoped, authority-bounded guarantees without changing the semantics.
pub fn image_generation_tool_verbose_description(name: &str) -> Option<&'static str> {
    Some(match name {
        "list_image_generation_targets" => {
            "List image-generation targets with their safe capability, health, freshness, and cost projections. Disabled targets are hidden by default and included only when include_disabled is true. Call this first, before generate_image, so you choose a target_id that exists and is healthy. It is strictly read-only discovery and never grants generation authority; it returns no secrets, headers, raw workflow, or credentials. Omitting a target later uses the configured default with one sample."
        }
        "generate_image" => {
            "Submit an image-generation job from a prompt, with optional per-target overrides, shared dimensions, references (attachment_id or daemon-local local_path), and a required output directory and base_stem. Call list_image_generation_targets first to pick a target_id; omitting targets uses the configured default with one sample. Raw URLs, provider JSON, workflow data, duplicate targets, and unknown fields are rejected. Dimensions resolve to exact, nearest supported, or provider default. Partial failure keeps successful slots published, cancellation is idempotent, and there is never a mid-job substitution."
        }
        "get_image_generation_job" => {
            "Return the durable status and safe result metadata for one image-generation job the current session is authorized to see. Use it to poll a job you submitted until it finishes. It is read-only and session-scoped: it never reveals another session's prompt, references, cost projections, filesystem paths, destinations, or artifacts, even if a job id leaks, and it grants no control over the job."
        }
        "cancel_image_generation_job" => {
            "Request cancellation of one image-generation job the current session is allowed to control. Use it to stop a job you no longer need. Cancellation is idempotent, so requesting it again has no additional effect, and only jobs this session owns can be cancelled; already successful slots stay published, and there is no hidden retry or target substitution afterward."
        }
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Tool trait implementations
// ---------------------------------------------------------------------------

/// `list_image_generation_targets` — read-only discovery.
pub struct ListImageGenerationTargetsTool;

#[async_trait::async_trait]
impl Tool for ListImageGenerationTargetsTool {
    fn name(&self) -> &str {
        "list_image_generation_targets"
    }

    fn description(&self) -> &str {
        image_generation_tool_description(self.name()).unwrap_or(
            "List image-generation targets with safe capability, health, freshness, and cost projections. Disabled targets require include_disabled. Call this first before generate_image.",
        )
    }

    fn verbose_description(&self) -> Option<String> {
        Some(image_generation_tool_verbose_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let obj = args.as_object().ok_or_else(|| {
            invalid_input("list_image_generation_targets arguments must be an object")
        })?;
        ensure_only_keys(
            obj,
            &["include_disabled"],
            "list_image_generation_targets arguments",
        )
        .map_err(|error| invalid_input(error.to_string()))?;
        let include_disabled = args
            .get("include_disabled")
            .map(|value| {
                value.as_bool().ok_or_else(|| {
                    invalid_input(
                        "list_image_generation_targets `include_disabled` must be a boolean",
                    )
                })
            })
            .transpose()?
            .unwrap_or(false);
        // Route through the session-scoped dispatch service, which owns the
        // live image runtime registry. The safe discovery projection is
        // produced by the registry: disabled targets are excluded by default
        // (`include_disabled = false`), and secrets, headers, raw workflow
        // JSON, endpoint origins, connected IPs, credential digests, and target
        // immutable identities are never surfaced. An empty configuration yields
        // an empty list (not an error). Discovery never grants generation
        // authority.
        let Some(service) = ctx.image_generation_dispatch.as_ref() else {
            return Ok(ToolOutput::text(
                "Image-generation target discovery is not available in this session. No \
                 provider was contacted."
                    .to_string(),
            ));
        };
        match service.list_targets(include_disabled) {
            crate::image_generation_agent_tools::ImageGenerationTargetDiscovery::DispatchUnavailable => {
                return Ok(ToolOutput::text(
                    crate::image_generation_job::DISPATCH_DISCOVERY_UNAVAILABLE.to_string(),
                ));
            }
            crate::image_generation_agent_tools::ImageGenerationTargetDiscovery::Targets(
                projections,
            ) if projections.is_empty() => {
                return Ok(ToolOutput::text(
                    "No image-generation targets are currently configured. Configure an image \
                     endpoint and target before calling `generate_image`."
                        .to_string(),
                ));
            }
            crate::image_generation_agent_tools::ImageGenerationTargetDiscovery::Targets(
                projections,
            ) => {
                let mut text = String::from("Image-generation targets:\n");
                for projection in &projections {
                    text.push_str(&format!(
                        "- `{}` (adapter `{}`, location `{}`, {}): health `{}`",
                        projection.target_id,
                        projection.adapter_kind,
                        projection.location_class.label(),
                        if projection.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        projection.health_state,
                    ));
                    if projection.capability_fresh {
                        text.push_str(", capability fresh");
                    }
                    if !projection.supported_formats.is_empty() {
                        text.push_str(&format!(
                            ", formats [{}]",
                            projection.supported_formats.join(", ")
                        ));
                    }
                    if let Some(max_w) = projection.maximum_width {
                        if let Some(max_h) = projection.maximum_height {
                            text.push_str(&format!(", max {max_w}x{max_h}"));
                        }
                    }
                    if !projection.allowed_parameters.is_empty() {
                        text.push_str(&format!(
                            ", parameters [{}]",
                            projection.allowed_parameters.join(", ")
                        ));
                    }
                    text.push('.');
                    text.push('\n');
                }
                text.push_str(
                    "Call `generate_image` with a `target_id` to generate images. Discovery never \
                     grants generation authority.",
                );
                Ok(ToolOutput::text(text))
            }
        }
    }
}

/// `generate_image` — submit an image generation job.
pub struct GenerateImageTool;

#[async_trait::async_trait]
impl Tool for GenerateImageTool {
    fn name(&self) -> &str {
        "generate_image"
    }

    fn description(&self) -> &str {
        image_generation_tool_description(self.name())
            .unwrap_or("Generate images from a prompt. Call list_image_generation_targets first.")
    }

    fn verbose_description(&self) -> Option<String> {
        Some(image_generation_tool_verbose_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn authorizes_own_effects(&self) -> bool {
        true
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        // Validate the arguments through the strict schema layer before
        // any provider contact. The composite authorization decision is
        // computed centrally before dispatch.
        validate_generate_image_args(&args).map_err(|error| invalid_input(error.to_string()))?;
        let mut dispatch_args = parse_generate_image_dispatch_args(&args)?;

        // Use the same native write-path authority as every other filesystem
        // writing tool before the image-specific approval is raised. Opening a
        // private directory proves containment, not that this agent/session was
        // authorized to write there.
        let requested_output = crate::tools::common::resolve(&dispatch_args.directory, &ctx.cwd);
        crate::tools::write::enforce_requested_write_scope(ctx, &requested_output, self.name())?;
        let checked_output = crate::tools::sandbox::check_native_access(
            ctx,
            &requested_output,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        crate::tools::sandbox::recheck_native_access_effect_boundary(
            &checked_output,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        dispatch_args.directory = checked_output.display().to_string();
        dispatch_args.normal_write_path_digest = Some(crate::intel::hex_lower(&Sha256::digest(
            dispatch_args.directory.as_bytes(),
        )));

        // `local_path` is not a durable attachment identity. Admit it through
        // normal read-path authority first; the session dispatch service below
        // then registers the checked daemon-local source as a typed attachment
        // before preflight, approval, leasing, or durable job creation.
        for reference in &mut dispatch_args.references {
            if let ImageReferenceTag::LocalPath { local_path } = reference {
                let requested = crate::tools::common::resolve(local_path, &ctx.cwd);
                let checked = crate::tools::sandbox::check_native_access(
                    ctx,
                    &requested,
                    crate::tools::shell_sandbox::SandboxPathAccess::Read,
                )
                .await?;
                crate::tools::sandbox::recheck_native_access_effect_boundary(
                    &checked,
                    crate::tools::shell_sandbox::SandboxPathAccess::Read,
                )
                .await?;
                *local_path = checked.display().to_string();
            }
        }

        // Route through the session-scoped dispatch funnel, which owns the
        // central [`crate::approval::Approver`] chokepoint and durable job
        // commit. Both the funnel and an approver must be present; otherwise the
        // request cannot be authorized in this session. Nothing here fabricates
        // an outcome, and no prompt text, raw path, secret, or reference byte is
        // ever surfaced — the dispatch service returns only redacted, model-safe
        // copy.
        let (Some(service), Some(approver)) = (
            ctx.image_generation_dispatch.as_ref(),
            ctx.approver.as_ref(),
        ) else {
            return Ok(ToolOutput::text(
                "Image generation dispatch is not available in this session. No job was created \
                 and no provider was contacted."
                    .to_string(),
            ));
        };

        if service
            .register_local_references(&ctx.session, &mut dispatch_args.references)
            .await
            .is_err()
        {
            return Ok(ToolOutput::text(
                "Image generation references are unavailable; no job was created and no provider was contacted."
                    .to_string(),
            ));
        }

        match service
            .dispatch_generate_image(&ctx.session, approver, &dispatch_args)
            .await?
        {
            crate::image_generation_job::GenerateImageDispatchOutcome::Queued { job_id } => {
                Ok(ToolOutput::text(format!(
                    "Image generation job `{job_id}` was authorized and queued. Use \
                     `get_image_generation_job` with this id to check status; \
                     `cancel_image_generation_job` requests idempotent cancellation."
                )))
            }
            crate::image_generation_job::GenerateImageDispatchOutcome::Refused { reason } => {
                // `reason` is already redacted, model-safe copy. No job was
                // created and no provider was contacted.
                Ok(ToolOutput::text(reason))
            }
            crate::image_generation_job::GenerateImageDispatchOutcome::Incompatible {
                alternatives,
            } => Ok(ToolOutput::text(format_incompatible_alternatives(
                &alternatives,
            ))),
        }
    }
}

/// Parse already-schema-validated `generate_image` arguments into the owned
/// dispatch DTO. Shared top-level `width`/`height`/`format` are the default for
/// every target; a per-target value overrides when present. `samples` defaults
/// to 1. When `targets` is omitted the schema means "the configured default
/// target with one sample". The dispatch service resolves that explicit
/// default-target marker against its live registry before projecting,
/// authorizing, or committing the request. References are a flat list;
/// each target is bound to every reference by index.
fn parse_generate_image_dispatch_args(
    args: &Value,
) -> Result<crate::image_generation_job::GenerateImageDispatchArgs> {
    let prompt = args
        .get("prompt")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`prompt` is required"))?
        .to_string();
    let directory = args
        .get("directory")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`directory` is required"))?
        .to_string();
    let base_stem = args
        .get("base_stem")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`base_stem` is required"))?
        .to_string();

    // Shared defaults. Absent dimensions are carried as 0, the "provider
    // default / nearest supported" sentinel for the non-optional DTO field;
    // absent format defaults to `png`.
    let shared_width = args.get("width").and_then(Value::as_u64).map(|v| v as u32);
    let shared_height = args.get("height").and_then(Value::as_u64).map(|v| v as u32);
    let shared_format = args
        .get("format")
        .and_then(Value::as_str)
        .map(str::to_string);

    let references: Vec<ImageReferenceTag> = args
        .get("references")
        .and_then(Value::as_array)
        .map(|refs| {
            refs.iter()
                .map(parse_image_reference_tag)
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    // The flat reference list carries no per-target binding in the schema, so
    // every target is bound to every reference by index.
    let all_reference_indices: Vec<usize> = (0..references.len()).collect();

    let targets = match args.get("targets").and_then(Value::as_array) {
        Some(entries) if !entries.is_empty() => entries
            .iter()
            .map(|entry| {
                parse_generate_image_dispatch_target(
                    entry,
                    shared_width,
                    shared_height,
                    shared_format.as_deref(),
                    &all_reference_indices,
                )
            })
            .collect::<Result<Vec<_>>>()?,
        _ => vec![crate::image_generation_job::GenerateImageDispatchTarget {
            // This marker is intentionally not an empty target id: an empty id
            // can accidentally be persisted or hashed as an authority fact.
            // It is private to the tool/service DTO boundary and must be
            // resolved to the one configured default before any projection.
            target_id: crate::image_generation_job::DEFAULT_IMAGE_TARGET_MARKER.to_string(),
            samples: 1,
            width: shared_width.unwrap_or(0),
            height: shared_height.unwrap_or(0),
            format: shared_format.clone().unwrap_or_else(|| "png".to_string()),
            parameters: BTreeMap::new(),
            reference_indices: all_reference_indices.clone(),
        }],
    };

    Ok(crate::image_generation_job::GenerateImageDispatchArgs {
        prompt,
        directory,
        base_stem,
        targets,
        references,
        normal_write_path_digest: None,
    })
}

/// Parse one schema-validated target entry into a resolved dispatch target,
/// folding in the shared width/height/format defaults.
fn parse_generate_image_dispatch_target(
    entry: &Value,
    shared_width: Option<u32>,
    shared_height: Option<u32>,
    shared_format: Option<&str>,
    all_reference_indices: &[usize],
) -> Result<crate::image_generation_job::GenerateImageDispatchTarget> {
    let target_id = entry
        .get("target_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("each target requires a `target_id`"))?
        .to_string();
    let samples = entry.get("samples").and_then(Value::as_u64).unwrap_or(1) as u32;
    let width = entry
        .get("width")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .or(shared_width)
        .unwrap_or(0);
    let height = entry
        .get("height")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .or(shared_height)
        .unwrap_or(0);
    let format = entry
        .get("format")
        .and_then(Value::as_str)
        .or(shared_format)
        .unwrap_or("png")
        .to_string();
    let parameters: BTreeMap<String, TypedParameter> = match entry.get("parameters") {
        Some(parameters) => serde_json::from_value(parameters.clone())
            .map_err(|err| invalid_input(format!("invalid target `parameters`: {err}")))?,
        None => BTreeMap::new(),
    };
    Ok(crate::image_generation_job::GenerateImageDispatchTarget {
        target_id,
        samples,
        width,
        height,
        format,
        parameters,
        reference_indices: all_reference_indices.to_vec(),
    })
}

/// Build a typed reference tag from a schema-validated reference object. The
/// validator guarantees exactly one of `attachment_id` / `local_path`.
fn parse_image_reference_tag(reference: &Value) -> Result<ImageReferenceTag> {
    if let Some(attachment_id) = reference.get("attachment_id").and_then(Value::as_str) {
        Ok(ImageReferenceTag::Attachment {
            attachment_id: attachment_id.to_string(),
        })
    } else if let Some(local_path) = reference.get("local_path").and_then(Value::as_str) {
        Ok(ImageReferenceTag::LocalPath {
            local_path: local_path.to_string(),
        })
    } else {
        Err(invalid_input(
            "each reference must tag exactly one of `attachment_id` or `local_path`",
        ))
    }
}

/// Render the redacted per-target capability alternatives from an
/// `Incompatible` dispatch outcome into model-safe text. Never surfaces a
/// prompt, raw path, secret, or reference byte.
fn format_incompatible_alternatives(
    alternatives: &[crate::image_generation_job::ImageGenerationTargetAlternativeV1],
) -> String {
    let mut lines = vec![
        "Image generation was not dispatched: the requested targets are incompatible with their \
         sealed capability. No job was created and no provider was contacted."
            .to_string(),
    ];
    for alternative in alternatives {
        lines.push(format!(
            "- target `{}`: formats [{}], max {}x{} — {}",
            alternative.target_id,
            alternative.supported_formats.join(", "),
            alternative.maximum_width,
            alternative.maximum_height,
            alternative.reason,
        ));
    }
    lines.join("\n")
}

/// `get_image_generation_job` — query durable job status.
pub struct GetImageGenerationJobTool;

#[async_trait::async_trait]
impl Tool for GetImageGenerationJobTool {
    fn name(&self) -> &str {
        "get_image_generation_job"
    }

    fn description(&self) -> &str {
        image_generation_tool_description(self.name())
            .unwrap_or("Get status and safe result metadata for an image-generation job.")
    }

    fn verbose_description(&self) -> Option<String> {
        Some(image_generation_tool_verbose_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let job_id = parse_exact_job_id_arg(&args, "get_image_generation_job")?;
        // Route through the session-scoped dispatch service, which owns the
        // owner-checked cockpit-db reader. Only jobs owned by the current session
        // are visible; a job that does not exist OR belongs to another session is
        // reported identically (existence-hiding). No prompt, path, cost,
        // destination, credential, or artifact byte is ever surfaced.
        let Some(service) = ctx.image_generation_dispatch.as_ref() else {
            return Ok(ToolOutput::text(
                "Image-generation job status is not available in this session.".to_string(),
            ));
        };
        // A job id that is not a valid identifier can match nothing; report it as
        // not-available exactly like an unknown or foreign job (existence-hiding).
        let Ok(parsed_job_id) = Uuid::parse_str(job_id.trim()) else {
            return Ok(ToolOutput::text(format!(
                "No image-generation job `{job_id}` is available to this session."
            )));
        };
        match service.job_status(&ctx.session, parsed_job_id).await? {
            crate::image_generation_job::GetImageJobStatusOutcome::Status {
                state,
                slot_count,
                cancellation_requested,
                terminal,
            } => {
                let mut text = format!(
                    "Image-generation job `{job_id}`: state `{state}`, {slot_count} slot(s){}.",
                    if cancellation_requested {
                        ", cancellation requested"
                    } else {
                        ""
                    }
                );
                if let Some(counts) = terminal {
                    text.push_str(&format!(
                        " Terminal `{}`: {} published, {} failed, {} cancelled, {} late-published, \
                         {} late-quarantined, {} discarded.",
                        counts.terminal_state,
                        counts.published,
                        counts.failed,
                        counts.cancelled,
                        counts.late_published,
                        counts.late_quarantined,
                        counts.discarded,
                    ));
                }
                Ok(ToolOutput::text(text))
            }
            crate::image_generation_job::GetImageJobStatusOutcome::NotFound => {
                Ok(ToolOutput::text(format!(
                    "No image-generation job `{job_id}` is available to this session."
                )))
            }
        }
    }
}

/// `cancel_image_generation_job` — idempotent cancellation.
pub struct CancelImageGenerationJobTool;

#[async_trait::async_trait]
impl Tool for CancelImageGenerationJobTool {
    fn name(&self) -> &str {
        "cancel_image_generation_job"
    }

    fn description(&self) -> &str {
        image_generation_tool_description(self.name())
            .unwrap_or("Request idempotent cancellation of an image-generation job.")
    }

    fn verbose_description(&self) -> Option<String> {
        Some(image_generation_tool_verbose_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let job_id = parse_exact_job_id_arg(&args, "cancel_image_generation_job")?;
        // Route through the session-scoped dispatch service, which owns the
        // owner-checked cancellation wrapper. Cancellation is idempotent; only
        // jobs the current session controls can be cancelled; a missing or
        // foreign job is reported identically (existence-hiding). Successful slots
        // remain published on partial failure, and there is no mid-job
        // substitution or unreserved retry.
        let Some(service) = ctx.image_generation_dispatch.as_ref() else {
            return Ok(ToolOutput::text(
                "Image-generation cancellation is not available in this session.".to_string(),
            ));
        };
        let Ok(parsed_job_id) = Uuid::parse_str(job_id.trim()) else {
            return Ok(ToolOutput::text(format!(
                "No image-generation job `{job_id}` is available to this session."
            )));
        };
        match service.cancel_job(&ctx.session, parsed_job_id).await? {
            crate::image_generation_job::CancelImageJobOutcome::CancellationRequested => {
                Ok(ToolOutput::text(format!(
                    "Cancellation requested for job `{job_id}`. The request is idempotent."
                )))
            }
            crate::image_generation_job::CancelImageJobOutcome::AlreadyTerminal => {
                Ok(ToolOutput::text(format!(
                    "Image-generation job `{job_id}` has already finished; there is nothing to cancel."
                )))
            }
            crate::image_generation_job::CancelImageJobOutcome::NotFound => Ok(ToolOutput::text(
                format!("No image-generation job `{job_id}` is available to this session."),
            )),
        }
    }
}

fn parse_exact_job_id_arg<'a>(args: &'a Value, tool: &str) -> Result<&'a str> {
    let object = args
        .as_object()
        .ok_or_else(|| invalid_input(format!("{tool} arguments must be an object")))?;
    ensure_only_keys(object, &["job_id"], &format!("{tool} arguments"))
        .map_err(|error| invalid_input(error.to_string()))?;
    object
        .get("job_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_input("`job_id` must be a non-empty string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use cockpit_config::config::image_generation::{
        IMAGE_GENERATION_ROUTE_PROFILE_VERSION, ImageAdapterKind, ImageCapabilityEvidence,
        ImageDimensionDescriptor, ImageDimensionRequestPolicy, ImageEndpoint, ImageFormat,
        ImageGenerationConfig, ImageGenerationTarget, ImageLocationClass, ImagePrice,
        ImageTargetIdentity, ReferenceImageSupport,
    };
    use cockpit_config::config::media_budget::MediaResourcePolicy;
    use cockpit_config::config::providers::CapabilityStatus;
    use cockpit_db::image_spend::{BudgetPolicy, ImageSpendSettings};

    use crate::daemon::principal::ClientPrincipal;
    use crate::daemon::proto::ResolveResponse;
    use crate::image_generation_job::{
        DispatchRevalidationRequest, ImageDispatchProofSource, ImageGenerationAdapter,
        ImageGenerationAdapterMap, ImageGenerationDispatchService, ImageGenerationDispatcher,
        ImageGenerationHandoffRequest, ImageGenerationHandoffResult,
    };
    use crate::image_generation_runtime::{
        CredentialIdentityDigest, DispatchProofBinding, ImageRuntimeRegistry, RuntimeError,
        dispatch_proof_support::{FixedClock, dispatchable_registry},
    };

    struct ToolImageClock;

    impl crate::media_reservation::MonotonicClock for ToolImageClock {
        fn now_ms(&self) -> u64 {
            100
        }
    }

    impl crate::image_generation_job::ImageGenerationDispatchClock for ToolImageClock {
        fn now_unix_ms(&self) -> i64 {
            1_700_000_000_100
        }
    }

    /// Uses the live runtime revalidation implementation for the scheduler half
    /// of the tool-boundary test. The database prepare transaction still checks
    /// this binding against the destination sealed by the authorized tool call.
    struct ToolRegistryProof {
        registry: ImageRuntimeRegistry,
        endpoint: ImageEndpoint,
        credential: CredentialIdentityDigest,
    }

    impl ImageDispatchProofSource for ToolRegistryProof {
        fn revalidate<'a>(
            &'a self,
            request: DispatchRevalidationRequest<'a>,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<DispatchProofBinding, RuntimeError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                self.registry
                    .revalidate_dispatch_binding(
                        &self.endpoint,
                        request.target_id,
                        &self.credential,
                    )
                    .await
            })
        }
    }

    /// A scripted adapter for the *worker* half of the integration test. Its
    /// count proves that a denied Tool::call leaves nothing for the scheduler,
    /// and that an allowed call reaches one real scheduler handoff.
    #[derive(Default)]
    struct CountingToolAdapter {
        calls: AtomicUsize,
    }

    impl crate::image_generation_job::image_generation_adapter_sealed::Sealed for CountingToolAdapter {}

    #[async_trait::async_trait]
    impl ImageGenerationAdapter for CountingToolAdapter {
        async fn handoff(
            &self,
            _request: &ImageGenerationHandoffRequest,
        ) -> ImageGenerationHandoffResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut cursor = std::io::Cursor::new(Vec::new());
            image::DynamicImage::new_rgba8(512, 512)
                .write_to(&mut cursor, image::ImageFormat::Png)
                .expect("scripted image encoding");
            ImageGenerationHandoffResult::AcceptedWithOutput {
                evidence: b"tool-boundary-accepted".to_vec(),
                output: crate::image_generation_job::ImageGenerationAcceptedOutput::Immediate {
                    bytes: cursor.into_inner(),
                },
            }
        }
    }

    fn tool_generation_endpoint() -> ImageEndpoint {
        ImageEndpoint {
            id: "tool-image-endpoint".to_string(),
            adapter: ImageAdapterKind::OpenaiImages,
            origin: "https://127.0.0.1".to_string(),
            path_prefix: None,
            credential_ref: None,
            headers: Vec::new(),
            allow_insecure_transport: false,
            location: ImageLocationClass::Local,
            enabled: true,
            route_profile_version: IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
            exclusive_server: false,
        }
    }

    fn tool_generation_config(endpoint: ImageEndpoint) -> ImageGenerationConfig {
        ImageGenerationConfig::new(
            vec![endpoint],
            vec![ImageGenerationTarget {
                id: "tool-image-target".to_string(),
                display_name: None,
                endpoint_id: "tool-image-endpoint".to_string(),
                identity: ImageTargetIdentity::HostedModel {
                    model: "gpt-image-test".to_string(),
                },
                enabled: true,
                is_default: true,
                formats: vec![ImageFormat::Png],
                reference_support: ReferenceImageSupport::Unsupported,
                max_reference_images: 0,
                max_samples: 1,
                max_outputs: 1,
                dimensions: ImageDimensionDescriptor::ProviderDefault,
                dimension_policy: ImageDimensionRequestPolicy::ProviderDefault,
                parameters: Vec::new(),
                openrouter_routing: None,
                generation_capability: ImageCapabilityEvidence::new(
                    CapabilityStatus::Unknown,
                    None,
                )
                .unwrap(),
                price: ImagePrice::Unknown,
            }],
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    #[cfg(feature = "extended")]
    async fn generation_tool_ctx(
        root: &std::path::Path,
    ) -> (
        ToolCtx,
        Arc<ImageGenerationDispatchService>,
        ToolRegistryProof,
    ) {
        let (mut ctx, db) = crate::tools::common::test_ctx_with_db(root);
        let endpoint = tool_generation_endpoint();
        let credential = CredentialIdentityDigest::from_sha256([7; 32]);
        let registry = Arc::new(
            dispatchable_registry(
                Arc::new(FixedClock(AtomicU64::new(0))),
                &endpoint,
                "tool-image-target",
                1,
                1,
                credential.clone(),
            )
            .await,
        );
        let proof_registry = dispatchable_registry(
            Arc::new(FixedClock(AtomicU64::new(0))),
            &endpoint,
            "tool-image-target",
            1,
            1,
            credential.clone(),
        )
        .await;
        db.save_image_spend_policy(
            ctx.session.project_id.clone(),
            ImageSpendSettings {
                request: BudgetPolicy::Unlimited,
                session: BudgetPolicy::Unlimited,
                project: BudgetPolicy::Unlimited,
                project_epoch: None,
            },
            None,
            100,
        )
        .await
        .unwrap();
        let service = Arc::new(ImageGenerationDispatchService::new(
            db,
            registry,
            Uuid::now_v7(),
            ClientPrincipal::owner(),
            1,
            BASE_TIER_KNOWN_COST_THRESHOLD_USD_MICROS,
            MediaResourcePolicy::default(),
            Arc::new(ToolImageClock),
            None,
            tool_generation_config(endpoint.clone()),
            ImageGenerationAdapterMap::new(),
        ));
        ctx.image_generation_dispatch = Some(service.clone());
        (
            ctx,
            service,
            ToolRegistryProof {
                registry: proof_registry,
                endpoint,
                credential,
            },
        )
    }

    fn tool_generation_args(output: &std::path::Path) -> Value {
        serde_json::json!({
            "prompt": "a test image",
            "directory": output.display().to_string(),
            "base_stem": "tool-image",
            "targets": [{
                "target_id": "tool-image-target",
                "width": 512,
                "height": 512,
                "format": "png"
            }]
        })
    }

    async fn reject_next_image_generation_prompt(ctx: &ToolCtx) -> String {
        let interrupt = loop {
            let open = ctx
                .session
                .db
                .list_open_interrupts(ctx.session.id)
                .await
                .unwrap();
            if let Some(interrupt) = open
                .iter()
                .find(|interrupt| ctx.interrupts.has_waiter(interrupt.interrupt_id))
            {
                break interrupt.clone();
            }
            tokio::task::yield_now().await;
        };
        let response = ResolveResponse::Single {
            selected_id: "reject".to_string(),
        };
        ctx.session
            .db
            .resolve_interrupt(interrupt.interrupt_id, &response)
            .await
            .unwrap();
        assert!(ctx.interrupts.resolve(interrupt.interrupt_id, response));
        interrupt.description
    }

    fn base_projection() -> ImageGenerationPlanProjection {
        ImageGenerationPlanProjection {
            destinations: vec![ProjectionDestination {
                target_id: "t1".to_string(),
                location_class: LocationClass::PublicCloud,
                adapter_kind: "openai_images".to_string(),
            }],
            prompt_collapsed: true,
            prompt_digest: "0".repeat(64),
            references: Vec::new(),
            target_requests: vec![ProjectionTargetRequest {
                target_id: "t1".to_string(),
                width: 1024,
                height: 1024,
                format: "png".to_string(),
                samples: 1,
                parameters: BTreeMap::new(),
            }],
            sizes: vec![ProjectionSize {
                target_id: "t1".to_string(),
                width: 1024,
                height: 1024,
            }],
            formats: vec!["png".to_string()],
            parameters: BTreeMap::new(),
            fanout: 1,
            total_outputs: 1,
            cost_maximum: Some(100_000),
            budget_disposition: BudgetDisposition::WithinBudget,
            output_directory: "/tmp/out".to_string(),
            output_base_stem: "image".to_string(),
            digest: String::new(),
        }
    }

    #[test]
    fn changed_reference_cannot_reuse_approval_digest() {
        let mut first = base_projection();
        first.references = vec![ProjectionReference {
            identity_digest: "a".repeat(64),
            thumbnail: false,
            destination_target_id: "t1".to_string(),
        }];
        let mut changed_reference = first.clone();
        changed_reference.references[0].identity_digest = "b".repeat(64);
        let mut changed_destination = first.clone();
        changed_destination.references[0].destination_target_id = "t2".to_string();
        assert_ne!(
            plan_projection_digest(&first).unwrap(),
            plan_projection_digest(&changed_reference).unwrap()
        );
        assert_ne!(
            plan_projection_digest(&first).unwrap(),
            plan_projection_digest(&changed_destination).unwrap()
        );
    }

    // The composite-decision tests that used to live here (hard gates,
    // ApprovalMode dispositions, unknown-cost dispatch) were REWRITTEN against
    // the real chokepoint `Approver::authorize(AuthorizationRequest::
    // ImageGeneration { .. })` and now live beside the Approver in
    // `approval/policy.rs` / `approval/mod.rs`, because that is the single
    // decision issuer after `authorize_generate_image` was deleted. The pure
    // risk-classifier tests (`classify_risk`) remain below: `classify_risk` is
    // the reusable pure classifier the Approver arm calls, not a decision
    // issuer, so its unit coverage stays here.

    // ---- Acceptance criterion 1: tool schemas ----

    #[test]
    fn image_generation_tool_schema_covers_all_four_tools() {
        for name in IMAGE_GENERATION_TOOL_NAMES {
            let schema = image_generation_tool_schema(name);
            assert_ne!(schema, Value::Null, "schema for `{name}` must not be null");
            assert_eq!(schema["type"], "object");
        }
        assert_eq!(image_generation_tool_schema("unknown"), Value::Null);
    }

    #[test]
    fn generate_image_schema_requires_prompt_directory_base_stem() {
        let schema = image_generation_tool_schema("generate_image");
        let required = schema["required"].as_array().unwrap();
        let required_names: Vec<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(required_names.contains(&"prompt"));
        assert!(required_names.contains(&"directory"));
        assert!(required_names.contains(&"base_stem"));
    }

    #[test]
    fn omitted_targets_use_the_explicit_default_target_marker() {
        let args = serde_json::json!({
            "prompt": "a small test image",
            "directory": "/safe/output",
            "base_stem": "image"
        });
        validate_generate_image_args(&args).unwrap();
        let parsed = parse_generate_image_dispatch_args(&args).unwrap();
        assert_eq!(parsed.targets.len(), 1);
        assert_eq!(
            parsed.targets[0].target_id,
            crate::image_generation_job::DEFAULT_IMAGE_TARGET_MARKER
        );
    }

    #[test]
    fn generate_image_schema_rejects_unknown_fields() {
        let schema = image_generation_tool_schema("generate_image");
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn generate_image_schema_documents_caps() {
        let schema = image_generation_tool_schema("generate_image");
        let targets = &schema["properties"]["targets"];
        assert_eq!(targets["maxItems"], MAX_GENERATE_IMAGE_TARGETS);
        let references = &schema["properties"]["references"];
        assert_eq!(references["maxItems"], MAX_GENERATE_IMAGE_REFERENCES);
    }

    #[test]
    fn generate_image_schema_parameters_match_the_typed_map_wire_contract() {
        let schema = image_generation_tool_schema("generate_image");
        let parameters = &schema["properties"]["targets"]["items"]["properties"]["parameters"];
        assert_eq!(parameters["type"], "object");
        assert_eq!(
            parameters["maxProperties"],
            MAX_GENERATE_IMAGE_TYPED_PARAMETERS
        );
        assert_eq!(parameters["propertyNames"]["minLength"], 1);
        assert_eq!(
            parameters["additionalProperties"]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn generate_image_schema_reference_tags_only_attachment_or_local_path() {
        let schema = image_generation_tool_schema("generate_image");
        let reference_item = &schema["properties"]["references"]["items"];
        let props = reference_item["properties"].as_object().unwrap();
        assert!(props.contains_key("attachment_id"));
        assert!(props.contains_key("local_path"));
        assert_eq!(reference_item["additionalProperties"], false);
    }

    #[test]
    fn list_targets_schema_is_read_only_and_has_no_secret_fields() {
        let schema = image_generation_tool_schema("list_image_generation_targets");
        let props = schema["properties"].as_object().unwrap();
        assert!(props.contains_key("include_disabled"));
        // No secret/header/workflow/grant/authority fields.
        for forbidden in [
            "secret",
            "header",
            "workflow",
            "grant",
            "authority",
            "token",
        ] {
            assert!(!props.keys().any(|k| k.contains(forbidden)), "{forbidden}");
        }
    }

    // ---- Acceptance criterion 2: discovery returns safe projections ----

    #[test]
    fn list_image_generation_targets_description_instructs_discovery_first() {
        let desc = image_generation_tool_description("list_image_generation_targets").unwrap();
        assert!(desc.to_lowercase().contains("first"));
        assert!(desc.to_lowercase().contains("no secrets"));
    }

    #[cfg(feature = "extended")]
    #[tokio::test]
    async fn image_generation_generate_tool_e2e_published() {
        let denied_root = tempfile::tempdir().unwrap();
        let denied_output = denied_root.path().join("denied-output");
        std::fs::create_dir(&denied_output).unwrap();
        let (denied_ctx, _denied_service, denied_proof) =
            generation_tool_ctx(denied_root.path()).await;
        denied_ctx
            .session
            .set_approval_mode(crate::config::extended::ApprovalMode::Manual);
        let (denied, approval_description) = tokio::join!(
            GenerateImageTool.call(tool_generation_args(&denied_output), &denied_ctx),
            reject_next_image_generation_prompt(&denied_ctx),
        );
        let denied = denied.unwrap();
        let digest_prefix = approval_description
            .split("(plan ")
            .nth(1)
            .and_then(|suffix| suffix.strip_suffix(")"))
            .expect("the real image authorization prompt must carry a plan digest prefix");
        assert_eq!(digest_prefix.len(), 12);
        assert!(
            digest_prefix
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert!(
            denied
                .content
                .contains("image generation was declined at the approval prompt"),
            "manual rejection must remain a refusal: {denied:?}"
        );

        let denied_adapter = CountingToolAdapter::default();
        let denied_pass = ImageGenerationDispatcher::new(denied_ctx.session.db.clone())
            .run_scheduler_pass(
                &denied_adapter,
                &denied_proof,
                Uuid::now_v7(),
                100,
                100,
                100,
                8,
            )
            .await
            .unwrap();
        assert_eq!(denied_pass.claimed, 0, "denial must leave no queued job");
        assert_eq!(denied_adapter.calls.load(Ordering::SeqCst), 0);

        let allowed_root = tempfile::tempdir().unwrap();
        let allowed_output = allowed_root.path().join("allowed-output");
        std::fs::create_dir(&allowed_output).unwrap();
        let (allowed_ctx, allowed_service, allowed_proof) =
            generation_tool_ctx(allowed_root.path()).await;
        // The test context's Yolo mode exercises the concrete Approver's
        // `AuthorizationRequest::ImageGeneration` allow path without a UI
        // interrupt; the service seals the resulting plan digest before queueing.
        let allowed = GenerateImageTool
            .call(tool_generation_args(&allowed_output), &allowed_ctx)
            .await
            .unwrap();
        let job_id = allowed
            .content
            .split('`')
            .nth(1)
            .and_then(|value| Uuid::parse_str(value).ok())
            .expect("authorized tool result must expose its queued job id");
        assert!(
            allowed.content.contains("authorized and queued"),
            "{allowed:?}"
        );
        assert!(matches!(
            allowed_service
                .job_status(&allowed_ctx.session, job_id)
                .await
                .unwrap(),
            crate::image_generation_job::GetImageJobStatusOutcome::Status {
                state,
                slot_count: 1,
                cancellation_requested: false,
                terminal: None,
            } if state == "queued"
        ));
        let created_at_unix_ms: i64 = allowed_ctx
            .session
            .db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT created_at_unix_ms FROM image_generation_jobs WHERE job_id=?1",
                    [job_id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(created_at_unix_ms, 1_700_000_000_100);

        let managed = allowed_root.path().join("managed-image-artifacts");
        cockpit_host::private_fs::ensure_private_dir(&managed).unwrap();
        let artifact_root = Arc::new(
            crate::image_generation_job::open_image_generation_artifact_root(&managed).unwrap(),
        );
        let allowed_adapter = CountingToolAdapter::default();
        let allowed_pass = ImageGenerationDispatcher::new(allowed_ctx.session.db.clone())
            .with_artifact_root(artifact_root)
            .run_scheduler_pass(
                &allowed_adapter,
                &allowed_proof,
                Uuid::now_v7(),
                100,
                100,
                100,
                8,
            )
            .await
            .unwrap();
        assert_eq!(allowed_pass.dispatched, 1);
        assert_eq!(allowed_adapter.calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            allowed_service
                .job_status(&allowed_ctx.session, job_id)
                .await
                .unwrap(),
            crate::image_generation_job::GetImageJobStatusOutcome::Status {
                terminal: Some(counts),
                ..
            } if counts.published == 1 && counts.failed == 0
        ));
    }

    #[cfg(feature = "extended")]
    #[tokio::test]
    async fn image_generation_cancellation_uses_wall_clock_unix_timestamp() {
        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("cancel-output");
        std::fs::create_dir(&output).unwrap();
        let (ctx, service, _) = generation_tool_ctx(root.path()).await;
        let queued = GenerateImageTool
            .call(tool_generation_args(&output), &ctx)
            .await
            .unwrap();
        let job_id = queued
            .content
            .split('`')
            .nth(1)
            .and_then(|value| Uuid::parse_str(value).ok())
            .unwrap();
        assert_eq!(
            service.cancel_job(&ctx.session, job_id).await.unwrap(),
            crate::image_generation_job::CancelImageJobOutcome::CancellationRequested
        );
        let requested_at_unix_ms: i64 = ctx
            .session
            .db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT requested_at_unix_ms FROM image_generation_cancellation_facts WHERE job_id=?1",
                    [job_id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(requested_at_unix_ms, 1_700_000_000_100);
    }

    // ---- Acceptance criterion 3: reference tests ----

    #[test]
    fn validate_generate_image_rejects_raw_url_reference() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "references": [{ "local_path": "https://example.com/cat.png" }]
        });
        let err = validate_generate_image_args(&args).unwrap_err().to_string();
        assert!(err.contains("raw URLs"), "{err}");
    }

    #[test]
    fn validate_generate_image_accepts_attachment_reference() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "references": [{ "attachment_id": "att-123" }]
        });
        validate_generate_image_args(&args).unwrap();
    }

    #[test]
    fn validate_generate_image_accepts_local_path_reference() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "references": [{ "local_path": "/tmp/cat.png" }]
        });
        validate_generate_image_args(&args).unwrap();
    }

    #[test]
    fn validate_generate_image_rejects_reference_with_both_tags() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "references": [{ "attachment_id": "att-123", "local_path": "/tmp/cat.png" }]
        });
        let err = validate_generate_image_args(&args).unwrap_err().to_string();
        assert!(err.contains("exactly one"));
    }

    #[test]
    fn validate_generate_image_rejects_reference_with_neither_tag() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "references": [{}]
        });
        let err = validate_generate_image_args(&args).unwrap_err().to_string();
        assert!(err.contains("exactly one"));
    }

    // ---- Acceptance criterion: default-target behavior, duplicate targets, unknown fields ----

    #[test]
    fn validate_generate_image_omitted_targets_means_default_one_sample() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image"
        });
        validate_generate_image_args(&args).unwrap();
    }

    #[test]
    fn validate_generate_image_rejects_duplicate_targets() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "targets": [
                { "target_id": "t1" },
                { "target_id": "t1" }
            ]
        });
        let err = validate_generate_image_args(&args).unwrap_err().to_string();
        assert!(err.contains("duplicate target_id"));
    }

    #[test]
    fn validate_generate_image_rejects_empty_prompt() {
        let args = serde_json::json!({
            "prompt": "   ",
            "directory": "/tmp/out",
            "base_stem": "image"
        });
        assert!(validate_generate_image_args(&args).is_err());
    }

    #[test]
    fn validate_generate_image_rejects_base_stem_with_slash() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "sub/image"
        });
        assert!(validate_generate_image_args(&args).is_err());
    }

    #[test]
    fn validate_generate_image_rejects_excessive_total_outputs() {
        let mut targets = Vec::new();
        for i in 0..16 {
            targets.push(serde_json::json!({ "target_id": format!("t{i}"), "samples": 64 }));
        }
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "targets": targets
        });
        let err = validate_generate_image_args(&args).unwrap_err().to_string();
        assert!(err.contains("total outputs"));
    }

    #[test]
    fn validate_generate_image_accepts_typed_parameter_map_wire_format() {
        let args = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "targets": [{
                "target_id": "t1",
                "parameters": {
                    "seed": { "type": "integer", "value": 7 },
                    "transparent": { "type": "boolean", "value": true },
                    "style": { "type": "text", "value": "illustration" }
                }
            }]
        });
        validate_generate_image_args(&args).unwrap();
    }

    #[test]
    fn validate_generate_image_rejects_parameter_shape_or_type_mismatch() {
        let base = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image",
            "targets": [{ "target_id": "t1" }]
        });

        let mut wrong_container = base.clone();
        wrong_container["targets"][0]["parameters"] = serde_json::json!([]);
        assert!(validate_generate_image_args(&wrong_container).is_err());

        let mut unknown_field = base.clone();
        unknown_field["targets"][0]["parameters"] = serde_json::json!({
            "seed": { "type": "integer", "value": 7, "provider": "ignored" }
        });
        assert!(validate_generate_image_args(&unknown_field).is_err());

        let mut wrong_type = base;
        wrong_type["targets"][0]["parameters"] = serde_json::json!({
            "seed": { "type": "integer", "value": "7" }
        });
        assert!(validate_generate_image_args(&wrong_type).is_err());
    }

    #[test]
    fn generate_image_validator_rejects_schema_unknowns_and_wrong_optional_containers() {
        let base = serde_json::json!({
            "prompt": "a cat",
            "directory": "/tmp/out",
            "base_stem": "image"
        });
        for malformed in [
            serde_json::json!({
                "prompt": "a cat", "directory": "/tmp/out", "base_stem": "image",
                "provider_payload": {}
            }),
            serde_json::json!({
                "prompt": "a cat", "directory": "/tmp/out", "base_stem": "image",
                "targets": {}
            }),
            serde_json::json!({
                "prompt": "a cat", "directory": "/tmp/out", "base_stem": "image",
                "targets": [{"target_id": "t1", "samples": "2"}]
            }),
            serde_json::json!({
                "prompt": "a cat", "directory": "/tmp/out", "base_stem": "image",
                "targets": [{"target_id": "t1", "workflow": {}}]
            }),
            serde_json::json!({
                "prompt": "a cat", "directory": "/tmp/out", "base_stem": "image",
                "references": {}
            }),
            serde_json::json!({
                "prompt": "a cat", "directory": "/tmp/out", "base_stem": "image",
                "references": [{"attachment_id": 7}]
            }),
        ] {
            assert!(
                validate_generate_image_args(&malformed).is_err(),
                "{malformed}"
            );
        }
        validate_generate_image_args(&base).unwrap();
    }

    #[tokio::test]
    async fn list_targets_rejects_unknown_fields_and_non_boolean_include_disabled() {
        let root = tempfile::tempdir().unwrap();
        let (ctx, _) = crate::tools::common::test_ctx_with_db(root.path());
        assert!(
            ListImageGenerationTargetsTool
                .call(serde_json::json!({"include_disabled": "false"}), &ctx)
                .await
                .is_err()
        );
        assert!(
            ListImageGenerationTargetsTool
                .call(serde_json::json!({"unexpected": true}), &ctx)
                .await
                .is_err()
        );
    }

    #[test]
    fn get_and_cancel_job_arguments_are_exact_objects() {
        for tool in ["get_image_generation_job", "cancel_image_generation_job"] {
            assert!(parse_exact_job_id_arg(&serde_json::json!(null), tool).is_err());
            assert!(parse_exact_job_id_arg(&serde_json::json!({"job_id": 7}), tool).is_err());
            assert!(
                parse_exact_job_id_arg(
                    &serde_json::json!({"job_id": Uuid::now_v7().to_string(), "extra": true}),
                    tool,
                )
                .is_err()
            );
            assert_eq!(
                parse_exact_job_id_arg(&serde_json::json!({"job_id": "job"}), tool).unwrap(),
                "job"
            );
        }
    }

    #[test]
    fn generate_image_uses_only_its_composite_authorization_chokepoint() {
        let tool = GenerateImageTool;
        assert_eq!(tool.effect(), ToolEffect::Dynamic);
        assert!(tool.authorizes_own_effects());
        assert!(!crate::engine::tool::tool_requires_permission(&tool));
    }

    #[test]
    fn typed_parameter_serde_rejects_unknown_fields() {
        let value = serde_json::json!({ "type": "integer", "value": 7, "extra": true });
        assert!(serde_json::from_value::<TypedParameter>(value).is_err());
    }

    // ---- Acceptance criterion 5: projection/digest tests ----

    #[test]
    fn digest_changes_on_authority_affecting_mutation() {
        let mut projection = base_projection();
        let digest1 = plan_projection_digest(&projection).unwrap();
        projection.fanout = 2;
        let digest2 = plan_projection_digest(&projection).unwrap();
        assert_ne!(digest1, digest2, "fanout change must change the digest");
    }

    #[test]
    fn digest_is_deterministic() {
        let projection = base_projection();
        let d1 = plan_projection_digest(&projection).unwrap();
        let d2 = plan_projection_digest(&projection).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn same_projection_produces_same_digest() {
        let projection = base_projection();
        let digest1 = plan_projection_digest(&projection).unwrap();
        let projection2 = projection.clone();
        let digest2 = plan_projection_digest(&projection2).unwrap();
        assert_eq!(
            digest1, digest2,
            "identical projections must produce identical digests"
        );
    }

    // ---- Acceptance criterion 6: grant tests ----

    // ---- Acceptance criterion 8: risk/spend tests ----

    #[test]
    fn base_threshold_is_250_000_micros() {
        assert_eq!(
            BASE_TIER_KNOWN_COST_THRESHOLD_USD_MICROS, 250_000,
            "the known-cost base-tier threshold is USD 0.25 (250_000 micros)"
        );
    }

    #[test]
    fn base_tier_single_target_single_output_known_cost_at_threshold() {
        let tier = classify_risk(1, 1, Some(250_000), false, 250_000);
        assert_eq!(tier, GenerateImageRiskTier::Base);
    }

    #[test]
    fn elevated_tier_when_cost_above_threshold() {
        let tier = classify_risk(1, 1, Some(250_001), false, 250_000);
        assert_eq!(tier, GenerateImageRiskTier::Elevated);
    }

    #[test]
    fn elevated_tier_when_fanout() {
        let tier = classify_risk(2, 2, Some(100), false, 250_000);
        assert_eq!(tier, GenerateImageRiskTier::Elevated);
    }

    #[test]
    fn elevated_tier_when_unknown_cost() {
        let tier = classify_risk(1, 1, None, false, 250_000);
        assert_eq!(tier, GenerateImageRiskTier::Elevated);
    }

    #[test]
    fn elevated_tier_when_reference_egress_unmatched() {
        let tier = classify_risk(1, 1, Some(100), true, 250_000);
        assert_eq!(tier, GenerateImageRiskTier::Elevated);
    }

    // The unknown-cost dispatch gate (all-Unlimited requirement) is now
    // enforced by the Approver arm; its coverage moved to
    // `approval/policy.rs` (`image_generation_unknown_cost_requires_all_unlimited`).

    // ---- Acceptance criterion 11: tool descriptions ----

    #[test]
    fn generate_image_description_explains_dimensions_and_partial_failure() {
        let desc = image_generation_tool_description("generate_image").unwrap();
        assert!(desc.to_lowercase().contains("dimensions"));
        assert!(desc.to_lowercase().contains("partial failure"));
        assert!(desc.to_lowercase().contains("cancellation"));
        assert!(desc.to_lowercase().contains("no mid-job substitution"));
    }

    #[test]
    fn all_four_tool_names_have_descriptions() {
        for name in IMAGE_GENERATION_TOOL_NAMES {
            assert!(
                image_generation_tool_description(name).is_some(),
                "`{name}` must have a description"
            );
        }
    }
}
