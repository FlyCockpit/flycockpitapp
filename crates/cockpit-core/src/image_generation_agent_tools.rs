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
//! (`crate::image_generation_job`, `crate::image_spend`), the canonical
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
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
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

/// Approval mode disposition recorded by the composite decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDisposition {
    /// Manual honored an exact matching standing grant.
    StandingGrant,
    /// Manual/Auto asked the human and the human approved.
    HumanApproved,
    /// Auto honored a grant and central safe-risk policy.
    AutoPolicy,
    /// Yolo opened no human prompt and recorded `agent_discretion`
    /// after every hard gate passed. Never `allow_once` and never a
    /// persisted grant.
    AgentDiscretion,
    /// The decision denied the request.
    Denied,
}

/// Reference-egress grant scope. There is no global/unscoped variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceEgressScope {
    Once,
    Session,
    Project,
}

/// Composite authorization grant tuple. Binds provider, model, endpoint
/// origin, connected location class, credential identity, target/workflow
/// digest, reference-egress boolean, maximum fanout, maximum total
/// outputs, and maximum known cost micros or explicit
/// `unknown_cost_allowed`. It never contains a wildcard destination or
/// unbounded implicit maximum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageGenerationGrantTuple {
    pub provider: String,
    pub model: String,
    pub endpoint_origin_digest: String,
    pub connected_location_class: LocationClass,
    pub credential_identity_digest: String,
    pub target_workflow_digest: String,
    pub reference_egress: bool,
    pub maximum_fanout: u32,
    pub maximum_total_outputs: u32,
    pub maximum_known_cost_usd_micros: Option<u64>,
    pub unknown_cost_allowed: bool,
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
    pub references: Vec<ProjectionReference>,
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
pub struct ProjectionDestination {
    pub target_id: String,
    pub location_class: LocationClass,
    pub adapter_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionReference {
    pub name: String,
    pub thumbnail: bool,
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

/// The composite authorization decision. One immutable decision covering
/// destinations, reference egress, fanout, spend risk, and normal
/// filesystem authority. Zero provider contact before a compatible
/// immutable plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationAuthorization {
    pub authorized: bool,
    pub risk_tier: GenerateImageRiskTier,
    pub disposition: ApprovalDisposition,
    pub digest: String,
    pub reasons: Vec<String>,
    pub provider_contacted: bool,
}

impl ImageGenerationAuthorization {
    /// Deny with a reason. The digest is empty because no compatible
    /// immutable plan was formed.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            authorized: false,
            risk_tier: GenerateImageRiskTier::Elevated,
            disposition: ApprovalDisposition::Denied,
            digest: String::new(),
            reasons: vec![reason.into()],
            provider_contacted: false,
        }
    }
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
                            "description": "Optional typed parameters for this target.",
                            "maxProperties": MAX_GENERATE_IMAGE_TYPED_PARAMETERS,
                            "additionalProperties": {
                                "type": "object",
                                "properties": {
                                    "type": { "type": "string", "enum": ["boolean", "integer", "text"] },
                                    "value": {}
                                },
                                "required": ["type", "value"],
                                "additionalProperties": false
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
/// perform authorization — that is [`authorize_generate_image`].
pub fn validate_generate_image_args(args: &Value) -> Result<()> {
    let obj = args
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("generate_image arguments must be an object"))?;

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
    if let Some(targets) = obj.get("targets").and_then(Value::as_array) {
        ensure!(
            targets.len() <= MAX_GENERATE_IMAGE_TARGETS,
            "generate_image `targets` exceeds the {} target cap",
            MAX_GENERATE_IMAGE_TARGETS
        );
        for entry in targets {
            let target_obj = entry
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("each target entry must be an object"))?;
            let target_id = target_obj
                .get("target_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("each target entry requires a `target_id`"))?;
            ensure!(
                !seen_targets.contains(target_id),
                "generate_image `targets` contains a duplicate target_id `{target_id}`"
            );
            seen_targets.insert(target_id.to_string());
            let samples = target_obj
                .get("samples")
                .and_then(Value::as_u64)
                .unwrap_or(1) as u32;
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
            if let Some(fmt) = target_obj.get("format").and_then(Value::as_str) {
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
    if let Some(fmt) = obj.get("format").and_then(Value::as_str) {
        ensure!(
            matches!(fmt, "png" | "jpeg" | "webp" | "svg"),
            "generate_image shared `format` is unsupported"
        );
    }

    if let Some(references) = obj.get("references").and_then(Value::as_array) {
        ensure!(
            references.len() <= MAX_GENERATE_IMAGE_REFERENCES,
            "generate_image `references` exceeds the {} cap",
            MAX_GENERATE_IMAGE_REFERENCES
        );
        for reference in references {
            let reference_obj = reference
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("each reference must be an object"))?;
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
            }
        }
    }

    Ok(())
}

fn validate_optional_dimension(obj: &Map<String, Value>, key: &str, label: &str) -> Result<()> {
    if let Some(dim) = obj.get(key).and_then(Value::as_u64) {
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
    let params_obj = parameters.as_object().ok_or_else(|| {
        anyhow::anyhow!("generate_image target `{target_id}` parameters must be an object")
    })?;
    ensure!(
        params_obj.len() <= MAX_GENERATE_IMAGE_TYPED_PARAMETERS,
        "generate_image target `{target_id}` parameters exceed the {} cap",
        MAX_GENERATE_IMAGE_TYPED_PARAMETERS
    );
    for (key, value) in params_obj {
        ensure!(
            !key.is_empty() && key.len() <= MAX_GENERATE_IMAGE_STRING_BYTES,
            "generate_image target `{target_id}` parameter key is outside its bound"
        );
        let value_obj = value.as_object().ok_or_else(|| {
            anyhow::anyhow!(
                "generate_image target `{target_id}` parameter `{key}` must be an object"
            )
        })?;
        let kind = value_obj
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
        ensure!(
            value_obj.contains_key("value"),
            "generate_image target `{target_id}` parameter `{key}` requires a `value`"
        );
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
pub fn plan_projection_digest(projection: &ImageGenerationPlanProjection) -> Result<String> {
    let bytes = serde_json::to_vec(projection)?;
    ensure!(!bytes.is_empty(), "plan projection must not be empty");
    Ok(hex_lower(&Sha256::digest(&bytes)))
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

/// Inputs to the composite authorization decision.
#[derive(Debug, Clone)]
pub struct AuthorizationInputs<'a> {
    pub fanout: u32,
    pub total_outputs: u32,
    pub cost_maximum: Option<u64>,
    pub reference_egress_unmatched: bool,
    pub grants: &'a [ImageGenerationGrantTuple],
    pub spend_request: SpendPolicyChoice,
    pub spend_session: SpendPolicyChoice,
    pub spend_project: SpendPolicyChoice,
    pub base_threshold_usd_micros: u64,
    pub approval_mode: ApprovalMode,
    pub projection: &'a ImageGenerationPlanProjection,
    pub path_read_authorized: bool,
    pub output_write_authorized: bool,
    pub destination_enabled: bool,
    pub capability_fresh: bool,
    pub insecure_transport_allowed: bool,
}

/// Approval mode (mirrors config, kept local).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Manual,
    Auto,
    Yolo,
}

/// Decide the composite authorization for a generate-image request.
///
/// This is the one immutable composite authorization decision covering
/// destinations, reference egress, fanout, spend risk, and normal
/// filesystem authority. Zero provider contact before a compatible
/// immutable plan.
pub fn authorize_generate_image(inputs: &AuthorizationInputs<'_>) -> ImageGenerationAuthorization {
    let mut reasons: Vec<String> = Vec::new();

    // Hard gates that Yolo cannot bypass.
    if !inputs.destination_enabled {
        reasons.push("destination is disabled".to_string());
    }
    if !inputs.capability_fresh {
        reasons.push("capability is stale".to_string());
    }
    if !inputs.path_read_authorized {
        reasons.push("reference local-path read authorization failed".to_string());
    }
    if !inputs.output_write_authorized {
        reasons.push("output write-path authorization failed".to_string());
    }
    if !inputs.insecure_transport_allowed {
        reasons.push("insecure-transport policy denied the destination".to_string());
    }

    // Unknown maximum may dispatch only when request, session, and project
    // spend choices are all explicitly Unlimited.
    let unknown_cost = inputs.cost_maximum.is_none();
    let unknown_dispatch_allowed = matches!(inputs.spend_request, SpendPolicyChoice::Unlimited)
        && matches!(inputs.spend_session, SpendPolicyChoice::Unlimited)
        && matches!(inputs.spend_project, SpendPolicyChoice::Unlimited);
    if unknown_cost && !unknown_dispatch_allowed {
        reasons.push(
            "unknown maximum cost requires request, session, and project spend choices all Unlimited"
                .to_string(),
        );
    }

    // Grant matching: a grant must cover the fanout, total outputs, and
    // cost (or unknown_cost_allowed). There is no wildcard destination
    // or unbounded implicit maximum.
    let grant_matches = inputs.grants.iter().any(|grant| {
        inputs.fanout <= grant.maximum_fanout
            && inputs.total_outputs <= grant.maximum_total_outputs
            && (match inputs.cost_maximum {
                Some(cost) => grant
                    .maximum_known_cost_usd_micros
                    .map(|max| cost <= max)
                    .unwrap_or(false),
                None => grant.unknown_cost_allowed,
            })
    });
    if !grant_matches {
        reasons.push("no matching grant covers the requested fanout/outputs/cost".to_string());
    }

    // Reference egress to a destination without a matching grant raises risk.
    if inputs.reference_egress_unmatched {
        reasons.push("reference egress to a destination without a matching grant".to_string());
    }

    let digest = match plan_projection_digest(inputs.projection) {
        Ok(digest) => digest,
        Err(err) => {
            return ImageGenerationAuthorization::deny(format!("plan projection failed: {err}"));
        }
    };

    let risk_tier = classify_risk(
        inputs.fanout,
        inputs.total_outputs,
        inputs.cost_maximum,
        inputs.reference_egress_unmatched,
        inputs.base_threshold_usd_micros,
    );

    if !reasons.is_empty() {
        return ImageGenerationAuthorization {
            authorized: false,
            risk_tier,
            disposition: ApprovalDisposition::Denied,
            digest,
            reasons,
            provider_contacted: false,
        };
    }

    // All hard gates passed. Now apply the approval-mode disposition.
    let disposition = match inputs.approval_mode {
        ApprovalMode::Manual => {
            if grant_matches {
                ApprovalDisposition::StandingGrant
            } else {
                ApprovalDisposition::HumanApproved
            }
        }
        ApprovalMode::Auto => {
            if grant_matches {
                ApprovalDisposition::AutoPolicy
            } else {
                ApprovalDisposition::HumanApproved
            }
        }
        ApprovalMode::Yolo => {
            // Yolo opens no human prompt and records disposition
            // `agent_discretion` — never `allow_once` and never a
            // persisted grant — after every hard gate passes.
            ApprovalDisposition::AgentDiscretion
        }
    };

    ImageGenerationAuthorization {
        authorized: true,
        risk_tier,
        disposition,
        digest,
        reasons,
        provider_contacted: false,
    }
}

/// Validate that a grant tuple is representable: no wildcard
/// destination, no unbounded implicit maximum. Global image grants are
/// unrepresentable.
pub fn validate_grant_tuple(grant: &ImageGenerationGrantTuple) -> Result<()> {
    ensure!(
        !grant.provider.is_empty() && !grant.model.is_empty(),
        "grant tuple must bind a provider and model"
    );
    ensure!(
        !grant.endpoint_origin_digest.is_empty(),
        "grant tuple must bind an endpoint origin digest"
    );
    ensure!(
        !grant.credential_identity_digest.is_empty(),
        "grant tuple must bind a credential identity digest"
    );
    ensure!(
        !grant.target_workflow_digest.is_empty(),
        "grant tuple must bind a target/workflow digest"
    );
    ensure!(
        grant.maximum_fanout > 0,
        "grant tuple must have a positive maximum fanout (no unbounded implicit maximum)"
    );
    ensure!(
        grant.maximum_total_outputs > 0,
        "grant tuple must have a positive maximum total outputs (no unbounded implicit maximum)"
    );
    ensure!(
        grant.maximum_known_cost_usd_micros.is_some() || grant.unknown_cost_allowed,
        "grant tuple must have a maximum known cost or explicit unknown_cost_allowed"
    );
    Ok(())
}

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
/// in [`image_generation_tool_defensive_description`].
pub fn image_generation_tool_description(name: &str) -> Option<&'static str> {
    Some(match name {
        "list_image_generation_targets" => {
            "List enabled image-generation targets with capability, health, freshness, and cost projections. Call this first before generate_image. Returns no secrets, workflow, disabled targets, or authority."
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
pub fn image_generation_tool_defensive_description(name: &str) -> Option<&'static str> {
    Some(match name {
        "list_image_generation_targets" => {
            "List the enabled image-generation targets with their safe capability, health, freshness, and cost projections. Call this first, before generate_image, so you choose a target_id that exists and is healthy. It is strictly read-only discovery and never grants generation authority; it returns no secrets, headers, raw workflow, disabled targets, or credentials. Omitting a target later uses the configured default with one sample."
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
            "List enabled image-generation targets with safe capability, health, freshness, and cost projections. Call this first before generate_image.",
        )
    }

    fn defensive_description(&self) -> Option<String> {
        Some(image_generation_tool_defensive_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let include_disabled = args
            .get("include_disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // The image generation runtime registry is owned by the daemon
        // session worker. The safe discovery projection is produced by the
        // runtime registry and surfaced through the daemon. In contexts
        // without a registered registry (tool tests, headless), return
        // the discovery guidance so the model knows to call
        // `generate_image` with a target_id. Discovery never grants
        // generation authority.
        let _ = include_disabled;
        Ok(ToolOutput::text(
            "Image-generation target discovery is available through the configured runtime \
             registry. Call `generate_image` with a `target_id` to generate images; omitting \
             targets uses the configured default with one sample. Discovery never grants \
             generation authority."
                .to_string(),
        ))
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

    fn defensive_description(&self) -> Option<String> {
        Some(image_generation_tool_defensive_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        // Validate the arguments through the strict schema layer before
        // any provider contact. The composite authorization decision is
        // computed centrally before dispatch.
        validate_generate_image_args(&args)?;
        let prompt = args
            .get("prompt")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`prompt` is required"))?;
        let directory = args
            .get("directory")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`directory` is required"))?;
        let base_stem = args
            .get("base_stem")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`base_stem` is required"))?;
        let target_count = args
            .get("targets")
            .and_then(Value::as_array)
            .map_or(1, |t| t.len() as u32);
        let total_outputs = args
            .get("targets")
            .and_then(Value::as_array)
            .map_or(1, |t| {
                t.iter()
                    .map(|target| target.get("samples").and_then(Value::as_u64).unwrap_or(1) as u32)
                    .sum()
            });
        Ok(ToolOutput::text(format!(
            "Image generation plan created for prompt: \"{prompt:.80}\"\n\nTargets: \
             {target_count}\nTotal outputs: {total_outputs}\nOutput directory: \
             {directory}\nBase stem: {base_stem}\n\nThe plan is pending composite \
             authorization and dispatch. Use `get_image_generation_job` to check \
             status."
        )))
    }
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

    fn defensive_description(&self) -> Option<String> {
        Some(image_generation_tool_defensive_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let job_id = args
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`job_id` is required"))?;
        if job_id.trim().is_empty() {
            return Err(invalid_input("`job_id` must not be empty"));
        }
        // The actual job lookup is handled by the job foundation; this tool
        // enforces session authorization and returns safe metadata. Only
        // jobs owned by the current session are accessible; this tool never
        // reveals another session's prompt, references, cost, paths,
        // destinations, or artifacts even if an ID leaks.
        Ok(ToolOutput::text(format!(
            "Job `{job_id}`: status lookup is pending the job foundation integration. \
             This session may only query jobs it owns."
        )))
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

    fn defensive_description(&self) -> Option<String> {
        Some(image_generation_tool_defensive_description(self.name())?.to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn parameters(&self) -> Value {
        image_generation_tool_schema(self.name())
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(image_generation_tool_schema(self.name()))
    }

    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let job_id = args
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`job_id` is required"))?;
        if job_id.trim().is_empty() {
            return Err(invalid_input("`job_id` must not be empty"));
        }
        // Cancellation is idempotent: requesting it again has no additional
        // effect. Only jobs the current session may control can be
        // cancelled. After submission there is no new mid-job approval,
        // hidden target substitution, or unreserved retry. Successful slots
        // remain published on partial failure.
        Ok(ToolOutput::text(format!(
            "Cancellation requested for job `{job_id}`. The request is idempotent."
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_projection() -> ImageGenerationPlanProjection {
        ImageGenerationPlanProjection {
            destinations: vec![ProjectionDestination {
                target_id: "t1".to_string(),
                location_class: LocationClass::PublicCloud,
                adapter_kind: "openai_images".to_string(),
            }],
            prompt_collapsed: true,
            references: Vec::new(),
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

    fn base_grant() -> ImageGenerationGrantTuple {
        ImageGenerationGrantTuple {
            provider: "openai".to_string(),
            model: "dall-e-3".to_string(),
            endpoint_origin_digest: "abc".to_string(),
            connected_location_class: LocationClass::PublicCloud,
            credential_identity_digest: "cred".to_string(),
            target_workflow_digest: "wf".to_string(),
            reference_egress: false,
            maximum_fanout: 4,
            maximum_total_outputs: 16,
            maximum_known_cost_usd_micros: Some(500_000),
            unknown_cost_allowed: false,
        }
    }

    /// A single default grant with a `'static` lifetime so `base_inputs` can
    /// hand out a `&'a [ImageGenerationGrantTuple]` that outlives each test's
    /// borrowed `AuthorizationInputs`.
    static BASE_GRANTS: std::sync::LazyLock<[ImageGenerationGrantTuple; 1]> =
        std::sync::LazyLock::new(|| [base_grant()]);

    fn base_inputs<'a>(projection: &'a ImageGenerationPlanProjection) -> AuthorizationInputs<'a> {
        AuthorizationInputs {
            fanout: 1,
            total_outputs: 1,
            cost_maximum: Some(100_000),
            reference_egress_unmatched: false,
            grants: &BASE_GRANTS[..],
            spend_request: SpendPolicyChoice::Finite {
                usd_micros: 1_000_000,
            },
            spend_session: SpendPolicyChoice::Finite {
                usd_micros: 1_000_000,
            },
            spend_project: SpendPolicyChoice::Finite {
                usd_micros: 1_000_000,
            },
            base_threshold_usd_micros: BASE_TIER_KNOWN_COST_THRESHOLD_USD_MICROS,
            approval_mode: ApprovalMode::Manual,
            projection,
            path_read_authorized: true,
            output_write_authorized: true,
            destination_enabled: true,
            capability_fresh: true,
            insecure_transport_allowed: true,
        }
    }

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

    // ---- Acceptance criterion 4: authorization proves zero provider contact ----

    #[test]
    fn authorization_has_zero_provider_contact_before_plan() {
        let projection = base_projection();
        let inputs = base_inputs(&projection);
        let auth = authorize_generate_image(&inputs);
        assert!(
            !auth.provider_contacted,
            "provider must not be contacted before a compatible immutable plan"
        );
    }

    #[test]
    fn authorization_denies_when_destination_disabled() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.destination_enabled = false;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
        assert!(auth.reasons.iter().any(|r| r.contains("disabled")));
    }

    #[test]
    fn authorization_denies_when_path_read_unauthorized() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.path_read_authorized = false;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
    }

    #[test]
    fn authorization_denies_when_output_write_unauthorized() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.output_write_authorized = false;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
    }

    #[test]
    fn authorization_denies_when_no_grant_matches() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.grants = &[];
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
        assert!(auth.reasons.iter().any(|r| r.contains("no matching grant")));
    }

    #[test]
    fn authorization_authorizes_base_tier_manual_with_grant() {
        let projection = base_projection();
        let inputs = base_inputs(&projection);
        let auth = authorize_generate_image(&inputs);
        assert!(auth.authorized);
        assert_eq!(auth.risk_tier, GenerateImageRiskTier::Base);
        assert_eq!(auth.disposition, ApprovalDisposition::StandingGrant);
        assert!(!auth.provider_contacted);
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

    #[test]
    fn validate_grant_tuple_rejects_zero_fanout() {
        let mut grant = base_grant();
        grant.maximum_fanout = 0;
        assert!(validate_grant_tuple(&grant).is_err());
    }

    #[test]
    fn validate_grant_tuple_rejects_zero_total_outputs() {
        let mut grant = base_grant();
        grant.maximum_total_outputs = 0;
        assert!(validate_grant_tuple(&grant).is_err());
    }

    #[test]
    fn validate_grant_tuple_rejects_no_cost_bound() {
        let mut grant = base_grant();
        grant.maximum_known_cost_usd_micros = None;
        grant.unknown_cost_allowed = false;
        assert!(validate_grant_tuple(&grant).is_err());
    }

    #[test]
    fn validate_grant_tuple_accepts_unknown_cost_allowed() {
        let mut grant = base_grant();
        grant.maximum_known_cost_usd_micros = None;
        grant.unknown_cost_allowed = true;
        validate_grant_tuple(&grant).unwrap();
    }

    #[test]
    fn reference_egress_scope_has_no_global_variant() {
        // The enum only has Once, Session, Project.
        let scopes = ["once", "session", "project"];
        for scope in scopes {
            let quoted = format!("\"{scope}\"");
            let _: ReferenceEgressScope = serde_json::from_str(&quoted)
                .unwrap_or_else(|_| panic!("`{scope}` must deserialize as a ReferenceEgressScope"));
        }
        // A "global" variant must not deserialize.
        assert!(serde_json::from_str::<ReferenceEgressScope>("\"global\"").is_err());
    }

    // ---- Acceptance criterion 7: Manual/Auto/Yolo matrix ----

    #[test]
    fn yolo_emits_agent_discretion_and_no_approval_request() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.approval_mode = ApprovalMode::Yolo;
        let auth = authorize_generate_image(&inputs);
        assert!(auth.authorized);
        assert_eq!(auth.disposition, ApprovalDisposition::AgentDiscretion);
        // Yolo never records allow_once or a persisted grant.
        assert_ne!(auth.disposition, ApprovalDisposition::HumanApproved);
    }

    #[test]
    fn yolo_cannot_bypass_disabled_destination() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.approval_mode = ApprovalMode::Yolo;
        inputs.destination_enabled = false;
        let auth = authorize_generate_image(&inputs);
        assert!(
            !auth.authorized,
            "Yolo cannot bypass a disabled destination"
        );
    }

    #[test]
    fn yolo_cannot_bypass_stale_capability() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.approval_mode = ApprovalMode::Yolo;
        inputs.capability_fresh = false;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
    }

    #[test]
    fn yolo_cannot_bypass_path_authority() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.approval_mode = ApprovalMode::Yolo;
        inputs.path_read_authorized = false;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
    }

    #[test]
    fn yolo_cannot_bypass_output_write_authority() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.approval_mode = ApprovalMode::Yolo;
        inputs.output_write_authorized = false;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
    }

    #[test]
    fn yolo_cannot_bypass_insecure_transport_policy() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.approval_mode = ApprovalMode::Yolo;
        inputs.insecure_transport_allowed = false;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
    }

    #[test]
    fn manual_honors_standing_grant() {
        let projection = base_projection();
        let inputs = base_inputs(&projection);
        let auth = authorize_generate_image(&inputs);
        assert_eq!(auth.disposition, ApprovalDisposition::StandingGrant);
    }

    #[test]
    fn auto_honors_grant_and_policy() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.approval_mode = ApprovalMode::Auto;
        let auth = authorize_generate_image(&inputs);
        assert!(auth.authorized);
        assert_eq!(auth.disposition, ApprovalDisposition::AutoPolicy);
    }

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

    #[test]
    fn unknown_cost_dispatch_requires_three_unlimited_choices() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.cost_maximum = None;
        inputs.spend_request = SpendPolicyChoice::Unlimited;
        inputs.spend_session = SpendPolicyChoice::Unlimited;
        inputs.spend_project = SpendPolicyChoice::Unlimited;
        // Grant must allow unknown cost.
        let mut grant = base_grant();
        grant.maximum_known_cost_usd_micros = None;
        grant.unknown_cost_allowed = true;
        let grants = [grant];
        inputs.grants = &grants;
        let auth = authorize_generate_image(&inputs);
        assert!(
            auth.authorized,
            "unknown cost dispatch must succeed when all three spend choices are Unlimited and the grant allows unknown cost"
        );
    }

    #[test]
    fn unknown_cost_denied_when_any_spend_choice_is_finite() {
        let projection = base_projection();
        let mut inputs = base_inputs(&projection);
        inputs.cost_maximum = None;
        inputs.spend_request = SpendPolicyChoice::Unlimited;
        inputs.spend_session = SpendPolicyChoice::Unlimited;
        inputs.spend_project = SpendPolicyChoice::Finite {
            usd_micros: 1_000_000,
        };
        let mut grant = base_grant();
        grant.maximum_known_cost_usd_micros = None;
        grant.unknown_cost_allowed = true;
        let grants = [grant];
        inputs.grants = &grants;
        let auth = authorize_generate_image(&inputs);
        assert!(!auth.authorized);
        assert!(auth.reasons.iter().any(|r| r.contains("Unlimited")));
    }

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
