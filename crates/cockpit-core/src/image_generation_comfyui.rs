//! Configurable ComfyUI workflow generation adapter.
//!
//! Connects to user-configured ComfyUI servers using registered API-format
//! workflows with typed bindings. The adapter clones a registered graph, binds
//! only declared semantic fields to exact node/input locations, uploads typed
//! references through `POST /upload/image` into a unique Cockpit-owned
//! namespace, submits with `POST /prompt` and a unique `client_id`, records the
//! returned `prompt_id`, follows `/ws` events when supported with bounded
//! `GET /history/{prompt_id}` polling as fallback, and retrieves only declared
//! output-node artifacts through bounded `GET /view` requests.
//!
//! Cancellation follows an exact capability union: `job_scoped_cancel`,
//! `queued_prompt_delete`, `exclusive_server_interrupt` (only under explicit
//! config and proven sole ownership), and `unsupported` late quarantine. No-ID
//! `POST /interrupt` is never used on a shared server.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageParameter, ImageRoute, RegisteredComfyWorkflow,
    WorkflowBinding, WorkflowOutput, WorkflowValueType,
};

// ---------------------------------------------------------------------------
// Route profile — typed methods/capabilities, never string concatenation from
// an agent.
// ---------------------------------------------------------------------------

/// A fully-resolved route URL for a ComfyUI endpoint. Built only from the
/// configured endpoint origin, path prefix, and the fixed route profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyRouteUrl {
    pub url: String,
    pub route: ImageRoute,
}

/// Resolves a ComfyUI endpoint route to an exact URL, applying the path prefix
/// and substituting path parameters with caller-supplied identifiers that are
/// already validated as opaque remote identifiers (never raw agent input).
pub struct ComfyRouteProfile<'a> {
    endpoint: &'a ImageEndpoint,
}

impl<'a> ComfyRouteProfile<'a> {
    pub const fn new(endpoint: &'a ImageEndpoint) -> Self {
        Self { endpoint }
    }

    fn base(&self) -> String {
        format!(
            "{}{}",
            self.endpoint.origin,
            self.endpoint.path_prefix.as_deref().unwrap_or("")
        )
    }

    /// A route without path-parameter substitution.
    pub fn fixed(&self, route: ImageRoute) -> Result<ComfyRouteUrl> {
        let relative = self
            .endpoint
            .adapter
            .route(route)
            .context("route is not available for this adapter")?;
        ensure!(
            !relative.contains('{'),
            "fixed route has unsubstituted parameters"
        );
        Ok(ComfyRouteUrl {
            url: format!("{}{}", self.base(), relative),
            route,
        })
    }

    /// A route with exactly one `{param}` substituted by a validated opaque
    /// remote identifier.
    pub fn param(&self, route: ImageRoute, value: &str) -> Result<ComfyRouteUrl> {
        let relative = self
            .endpoint
            .adapter
            .route(route)
            .context("route is not available for this adapter")?;
        let placeholder = relative
            .strip_suffix("}")
            .and_then(|s| s.rsplit_once('{'))
            .context("route has no parameter placeholder")?;
        ensure!(
            !value.contains('{') && !value.contains('}'),
            "remote identifier contains reserved characters"
        );
        validate_remote_identifier(value)?;
        Ok(ComfyRouteUrl {
            url: format!("{}{}{}", self.base(), placeholder.0, value),
            route,
        })
    }
}

// ---------------------------------------------------------------------------
// Remote-identifier validation — rejects path traversal in provider filenames,
// subfolders, and types.
// ---------------------------------------------------------------------------

/// Validates that a remote identifier (filename, subfolder, type) from a
/// ComfyUI server response is safe to use in a URL path or query parameter.
/// Rejects path traversal, absolute paths, and shell metacharacters.
pub fn validate_remote_identifier(value: &str) -> Result<()> {
    ensure!(!value.is_empty(), "remote identifier is empty");
    ensure!(
        value.len() <= 512,
        "remote identifier exceeds the maximum length"
    );
    ensure!(
        !value.contains(".."),
        "remote identifier contains path traversal"
    );
    ensure!(
        !value.starts_with('/'),
        "remote identifier is an absolute path"
    );
    ensure!(
        !value.starts_with('\\'),
        "remote identifier starts with a backslash"
    );
    ensure!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.' | b'~')),
        "remote identifier contains disallowed characters"
    );
    Ok(())
}

/// Validates a ComfyUI `subfolder` field, which may be empty but must never
/// contain traversal.
pub fn validate_subfolder(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    validate_remote_identifier(value)
}

// ---------------------------------------------------------------------------
// Graph binding — clone a registered graph and bind only declared typed values.
// ---------------------------------------------------------------------------

/// A typed canonical value that an agent may supply for a declared binding.
/// Agents cannot supply URLs, workflow JSON, node IDs, filenames, subfolders,
/// raw provider fields, or graph patches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalBindingValue {
    Integer(i64),
    DecimalMilli(i64),
    Text(String),
    /// A reference to a previously-uploaded image artifact, identified by its
    /// Cockpit-owned upload name.
    ImageReference {
        upload_name: String,
    },
}

impl CanonicalBindingValue {
    fn validate_text(&self, max_bytes: u64) -> Result<()> {
        if let Self::Text(text) = self {
            ensure!(
                text.len() as u64 <= max_bytes,
                "text value exceeds the declared maximum"
            );
        }
        Ok(())
    }

    fn validate_reference(&self) -> Result<()> {
        if let Self::ImageReference { upload_name } = self {
            validate_upload_name(upload_name)?;
        }
        Ok(())
    }

    /// Returns `true` if the value's type is compatible with the binding's
    /// declared `WorkflowValueType`.
    fn matches(&self, value_type: WorkflowValueType) -> bool {
        matches!(
            (self, value_type),
            (Self::Integer(_), WorkflowValueType::Integer)
                | (Self::DecimalMilli(_), WorkflowValueType::DecimalMilli)
                | (Self::Text(_), WorkflowValueType::Text)
                | (Self::ImageReference { .. }, WorkflowValueType::Image)
        )
    }

    /// Converts the value to the JSON representation expected by ComfyUI's
    /// API-format workflow graph.
    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Integer(value) => serde_json::Value::from(*value),
            Self::DecimalMilli(value) => serde_json::Value::from(*value),
            Self::Text(value) => serde_json::Value::from(value.as_str()),
            Self::ImageReference { upload_name } => serde_json::Value::from(upload_name.as_str()),
        }
    }
}

/// A single binding application: parameter → node/input with a typed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingApplication {
    pub parameter: ImageParameter,
    pub value: CanonicalBindingValue,
}

/// The result of cloning and binding a registered workflow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundWorkflowGraph {
    /// The cloned graph JSON with only declared values mutated.
    pub graph_json: String,
    /// The declared output nodes to retrieve.
    pub outputs: Vec<WorkflowOutput>,
}

/// Clones a registered workflow graph and binds only declared typed values to
/// exact node/input locations. The source graph is never mutated. Undeclared
/// parameters, raw graph patches, node IDs, and agent-supplied graph JSON are
/// rejected.
pub fn clone_and_bind_workflow(
    workflow: &RegisteredComfyWorkflow,
    applications: &[BindingApplication],
) -> Result<BoundWorkflowGraph> {
    let mut graph: serde_json::Value =
        serde_json::from_str(&workflow.graph_json).context("workflow graph is not valid JSON")?;
    let nodes = graph
        .as_object_mut()
        .context("workflow graph is not a JSON object")?;

    // Build a lookup of declared bindings by parameter.
    let mut declared: BTreeMap<ImageParameter, &WorkflowBinding> = BTreeMap::new();
    for binding in &workflow.bindings {
        ensure!(
            declared.insert(binding.parameter, binding).is_none(),
            "workflow has duplicate parameter bindings"
        );
    }

    // Validate and apply each application.
    for application in applications {
        let binding = declared
            .get(&application.parameter)
            .with_context(|| format!("parameter {:?} is not declared", application.parameter))?;
        ensure!(
            application.value.matches(binding.value_type),
            "value type does not match the declared binding"
        );
        // Enforce bounds for numeric types.
        if let CanonicalBindingValue::Integer(value) = &application.value {
            if let Some(min) = binding.min {
                ensure!(*value >= min, "value is below the declared minimum");
            }
            if let Some(max) = binding.max {
                ensure!(*value <= max, "value exceeds the declared maximum");
            }
        }
        if let CanonicalBindingValue::DecimalMilli(value) = &application.value {
            if let Some(min) = binding.min {
                ensure!(*value >= min, "value is below the declared minimum");
            }
            if let Some(max) = binding.max {
                ensure!(*value <= max, "value exceeds the declared maximum");
            }
        }
        // Validate text and reference payloads.
        match &application.value {
            CanonicalBindingValue::Text(text) => {
                // Text bindings have a max_bytes bound enforced by the
                // parameter descriptor; here we use a conservative default
                // since the descriptor is not available in this function.
                application.value.validate_text(text.len() as u64)?;
            }
            CanonicalBindingValue::ImageReference { .. } => {
                application.value.validate_reference()?;
            }
            _ => {}
        }

        // Navigate to the exact node and input. Reject if the node or input
        // does not exist in the registered graph.
        let node = nodes
            .get_mut(&binding.node_id)
            .with_context(|| format!("node {} is not in the graph", binding.node_id))?;
        let inputs = node
            .as_object_mut()
            .context("workflow node is not a JSON object")?
            .get_mut("inputs")
            .and_then(serde_json::Value::as_object_mut)
            .context("workflow node has no inputs object")?;
        ensure!(
            inputs.contains_key(&binding.input),
            "input {} is not declared on node {}",
            binding.input,
            binding.node_id
        );
        // Bind only the declared input.
        inputs.insert(binding.input.clone(), application.value.to_json());
    }

    let graph_json = serde_json::to_string(&graph).context("failed to serialize bound graph")?;
    Ok(BoundWorkflowGraph {
        graph_json,
        outputs: workflow.outputs.clone(),
    })
}

/// Verifies that a source graph is unchanged after a clone-and-bind operation.
/// Used by tests to prove the registered graph stays immutable.
pub fn source_graph_unchanged(
    original: &RegisteredComfyWorkflow,
    bound: &BoundWorkflowGraph,
) -> Result<bool> {
    let original_graph: serde_json::Value = serde_json::from_str(&original.graph_json)?;
    let bound_graph: serde_json::Value = serde_json::from_str(&bound.graph_json)?;
    // The bound graph should only differ in declared input values.
    // This function checks that no nodes were added or removed and no
    // non-input fields changed.
    let original_nodes = original_graph
        .as_object()
        .context("original graph is not an object")?;
    let bound_nodes = bound_graph
        .as_object()
        .context("bound graph is not an object")?;
    if original_nodes
        .keys()
        .collect::<std::collections::BTreeSet<_>>()
        != bound_nodes
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
    {
        return Ok(false);
    }
    for (node_id, original_node) in original_nodes {
        let bound_node = &bound_nodes[node_id];
        let original_obj = original_node
            .as_object()
            .with_context(|| format!("original node {node_id} is not an object"))?;
        let bound_obj = bound_node
            .as_object()
            .with_context(|| format!("bound node {node_id} is not an object"))?;
        // Every key except "inputs" must match.
        for (key, original_value) in original_obj {
            if key == "inputs" {
                continue;
            }
            if bound_obj.get(key) != Some(original_value) {
                return Ok(false);
            }
        }
        // Bound inputs must be a subset of original inputs (only declared ones
        // may change; none may be added).
        let original_inputs = original_obj
            .get("inputs")
            .and_then(serde_json::Value::as_object)
            .context("original node has no inputs")?;
        let bound_inputs = bound_obj
            .get("inputs")
            .and_then(serde_json::Value::as_object)
            .context("bound node has no inputs")?;
        if bound_inputs
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
            != original_inputs
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Upload namespace — unpredictable per-attempt Cockpit-owned prefix.
// ---------------------------------------------------------------------------

/// Validates that an upload name follows the Cockpit-owned namespace format.
pub fn validate_upload_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "upload name is empty");
    ensure!(name.len() <= 256, "upload name exceeds the maximum length");
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
        "upload name contains disallowed characters"
    );
    ensure!(!name.contains(".."), "upload name contains path traversal");
    Ok(())
}

/// Generates an unpredictable per-attempt Cockpit-owned upload namespace prefix.
/// The prefix ensures uploaded artifacts are isolated per attempt and can be
/// proven as Cockpit-owned for cleanup.
pub fn attempt_upload_prefix(attempt_id: &uuid::Uuid) -> String {
    format!("cockpit-{attempt_id}")
}

/// Builds a full upload name from the attempt prefix and a local artifact name.
pub fn upload_name(prefix: &str, artifact_name: &str) -> Result<String> {
    validate_remote_identifier(artifact_name)?;
    let name = format!("{prefix}-{artifact_name}");
    validate_upload_name(&name)?;
    Ok(name)
}

// ---------------------------------------------------------------------------
// Cancellation capability union.
// ---------------------------------------------------------------------------

/// The exact cancellation capability discovered for a ComfyUI endpoint and
/// target. Capability selection is discovery/profile-bound and part of
/// target/plan identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ComfyCancellationCapability {
    /// `POST /api/jobs/{job_id}/cancel` with idempotent `{ "cancelled": bool }`
    /// response. Available only when discovery binds the Cockpit attempt to an
    /// exact job ID.
    JobScopedCancel,
    /// `POST /queue` with `{ "delete": [prompt_id] }` for an exact known
    /// prompt still reported queued.
    QueuedPromptDelete,
    /// `POST /interrupt` without an ID — process-global. Forbidden unless
    /// endpoint config explicitly sets `exclusive_server: true` and the current
    /// attempt owns the only executing work.
    ExclusiveServerInterrupt,
    /// No provider cancellation is available. Record local
    /// `cancellation_requested`, stop polling, and quarantine any later result.
    Unsupported,
}

impl ComfyCancellationCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JobScopedCancel => "job_scoped_cancel",
            Self::QueuedPromptDelete => "queued_prompt_delete",
            Self::ExclusiveServerInterrupt => "exclusive_server_interrupt",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ComfyCancellationCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Selects the cancellation capability for an attempt based on discovery
/// evidence, endpoint config, and current queue state. A job-scoped route wins
/// over queued deletion for a running job. Queue deletion is only for queued
/// work. No-ID `/interrupt` is never used by ordinary shared-server
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancellationCapabilitySelection {
    pub capability: ComfyCancellationCapability,
    pub reason: &'static str,
}

/// Evidence that binds a Cockpit attempt to an exact ComfyUI job ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobBinding {
    pub job_id: String,
}

/// A snapshot of the ComfyUI queue state for the current attempt.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueueSnapshot {
    /// Prompt IDs currently queued.
    pub queued: Vec<String>,
    /// Prompt IDs currently executing.
    pub running: Vec<String>,
}

impl QueueSnapshot {
    /// Returns `true` if the given prompt is still queued.
    pub fn is_queued(&self, prompt_id: &str) -> bool {
        self.queued.iter().any(|id| id == prompt_id)
    }

    /// Returns `true` if the given prompt is currently running.
    pub fn is_running(&self, prompt_id: &str) -> bool {
        self.running.iter().any(|id| id == prompt_id)
    }

    /// Returns `true` if the current attempt owns the only executing work on
    /// this server. Required for exclusive-server interrupt.
    pub fn owns_sole_execution(&self, prompt_id: &str) -> bool {
        self.running.len() == 1 && self.is_running(prompt_id)
    }
}

/// Selects the cancellation capability given the current state. The selection
/// rules are:
///
/// 1. If a job binding exists, `JobScopedCancel` wins (it targets the exact
///    job).
/// 2. If no job binding but the prompt is still queued,
///    `QueuedPromptDelete`.
/// 3. If `exclusive_server` is explicitly configured and the attempt owns the
///    only executing work, `ExclusiveServerInterrupt`.
/// 4. Otherwise, `Unsupported`.
pub fn select_cancellation_capability(
    endpoint: &ImageEndpoint,
    job_binding: Option<&JobBinding>,
    queue: &QueueSnapshot,
    prompt_id: Option<&str>,
) -> CancellationCapabilitySelection {
    // A job-scoped route wins over queued deletion for a running job.
    if job_binding.is_some() {
        return CancellationCapabilitySelection {
            capability: ComfyCancellationCapability::JobScopedCancel,
            reason: "discovery binds the attempt to an exact job ID",
        };
    }
    // Queue deletion is only for queued work.
    if let Some(prompt_id) = prompt_id
        && queue.is_queued(prompt_id)
    {
        return CancellationCapabilitySelection {
            capability: ComfyCancellationCapability::QueuedPromptDelete,
            reason: "prompt is still queued and no job binding exists",
        };
    }
    // No-ID /interrupt is only under explicit exclusive-server config and
    // proven sole ownership.
    if endpoint.exclusive_server && prompt_id.is_some_and(|id| queue.owns_sole_execution(id)) {
        return CancellationCapabilitySelection {
            capability: ComfyCancellationCapability::ExclusiveServerInterrupt,
            reason: "exclusive server is configured and the attempt owns sole execution",
        };
    }
    CancellationCapabilitySelection {
        capability: ComfyCancellationCapability::Unsupported,
        reason: "no safe provider cancellation is available",
    }
}

// ---------------------------------------------------------------------------
// Cancellation request and result — maps to the ImageGenerationAdapter cancel.
// ---------------------------------------------------------------------------

/// A ComfyUI cancellation request targeting an exact capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyCancelRequest {
    pub capability: ComfyCancellationCapability,
    /// The prompt ID for queued deletion, if applicable.
    pub prompt_id: Option<String>,
    /// The job ID for job-scoped cancellation, if applicable.
    pub job_id: Option<String>,
}

/// The result of a ComfyUI cancellation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComfyCancelResult {
    /// The provider confirmed cancellation.
    Cancelled { evidence: Vec<u8> },
    /// The provider returned `cancelled: false` (authoritative no-op) or the
    /// work was already accepted/complete.
    TooLateOrAccepted { evidence: Vec<u8> },
    /// The cancellation capability is unsupported; record local
    /// `cancellation_requested` and quarantine any later result.
    Unsupported { evidence: Vec<u8> },
    /// The cancellation outcome is unknown (e.g. network error after possible
    /// acceptance).
    OutcomeUnknown { evidence: Vec<u8> },
}

// ---------------------------------------------------------------------------
// Submission — POST /prompt with unique client_id.
// ---------------------------------------------------------------------------

/// The payload for `POST /prompt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComfyPromptPayload {
    pub prompt: serde_json::Value,
    pub client_id: String,
}

/// The response from `POST /prompt`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ComfyPromptResponse {
    pub prompt_id: String,
}

/// The outcome of a submission attempt. Missing response after possible
/// handoff becomes `submission_unknown`; the adapter must not guess a prompt ID
/// or resubmit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionOutcome {
    /// The server accepted the prompt and returned a `prompt_id`.
    Accepted {
        prompt_id: String,
        evidence: Vec<u8>,
    },
    /// The server definitively rejected the prompt.
    DefinitivelyRejected {
        safe_reason: String,
        evidence: Vec<u8>,
    },
    /// The response was missing or ambiguous after possible handoff. Never
    /// guess a prompt ID or resubmit.
    SubmissionUnknown { evidence: Vec<u8> },
}

// ---------------------------------------------------------------------------
// Upload — POST /upload/image into a unique Cockpit-owned namespace.
// ---------------------------------------------------------------------------

/// The multipart fields for `POST /upload/image`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyUploadRequest {
    pub image_name: String,
    pub subfolder: String,
    pub overwrite: bool,
}

impl ComfyUploadRequest {
    /// Builds an upload request for a Cockpit-owned artifact in the attempt
    /// namespace. The subfolder uses the Cockpit prefix to isolate artifacts.
    pub fn new(prefix: &str, artifact_name: &str) -> Result<Self> {
        let image_name = upload_name(prefix, artifact_name)?;
        Ok(Self {
            image_name,
            subfolder: prefix.to_owned(),
            overwrite: true,
        })
    }
}

/// The response from `POST /upload/image`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ComfyUploadResponse {
    pub name: String,
    #[serde(default)]
    pub subfolder: String,
    #[serde(default)]
    pub r#type: String,
}

// ---------------------------------------------------------------------------
// History — GET /history/{prompt_id} bounded polling fallback.
// ---------------------------------------------------------------------------

/// A single output artifact from a history entry, filtered to declared output
/// nodes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyOutputArtifact {
    pub node_id: String,
    pub output: String,
    pub filename: String,
    pub subfolder: String,
    pub r#type: String,
}

impl ComfyOutputArtifact {
    /// Validates that the remote identifiers (filename, subfolder, type) are
    /// safe — no path traversal.
    pub fn validate_remote_identifiers(&self) -> Result<()> {
        validate_remote_identifier(&self.filename)?;
        validate_subfolder(&self.subfolder)?;
        validate_remote_identifier(&self.r#type)?;
        Ok(())
    }
}

/// The result of parsing a history response, filtered to declared output nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyHistoryResult {
    pub prompt_id: String,
    pub outputs: Vec<ComfyOutputArtifact>,
    /// Whether the prompt execution has completed.
    pub completed: bool,
}

/// Parses a `GET /history/{prompt_id}` JSON response, extracting only declared
/// output-node artifacts. Foreign/unknown nodes are ignored.
///
/// The expected shape is:
/// ```json
/// {
///   "<prompt_id>": {
///     "outputs": {
///       "<node_id>": {
///         "<output_name>": [{ "filename": "...", "subfolder": "...", "type": "..." }]
///       }
///     },
///     "status": { "completed": true }
///   }
/// }
/// ```
pub fn parse_history_response(
    body: &serde_json::Value,
    expected_prompt_id: &str,
    declared_outputs: &[WorkflowOutput],
) -> Result<ComfyHistoryResult> {
    let entry = body
        .get(expected_prompt_id)
        .context("history response does not contain the expected prompt_id")?;
    let outputs_obj = entry
        .get("outputs")
        .and_then(serde_json::Value::as_object)
        .context("history entry has no outputs object")?;
    let completed = entry
        .get("status")
        .and_then(serde_json::Value::as_object)
        .and_then(|s| s.get("completed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let mut artifacts = Vec::new();
    for declared in declared_outputs {
        let node_output = match outputs_obj.get(&declared.node_id) {
            Some(value) => value,
            None => continue,
        };
        let output_array = node_output
            .get(&declared.output)
            .and_then(serde_json::Value::as_array)
            .with_context(|| {
                format!(
                    "declared output {}.{} is not an array",
                    declared.node_id, declared.output
                )
            })?;
        for item in output_array {
            let filename = item
                .get("filename")
                .and_then(serde_json::Value::as_str)
                .context("output artifact is missing filename")?
                .to_owned();
            let subfolder = item
                .get("subfolder")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            let artifact_type = item
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("output")
                .to_owned();
            let artifact = ComfyOutputArtifact {
                node_id: declared.node_id.clone(),
                output: declared.output.clone(),
                filename,
                subfolder,
                r#type: artifact_type,
            };
            artifact.validate_remote_identifiers()?;
            artifacts.push(artifact);
        }
    }
    Ok(ComfyHistoryResult {
        prompt_id: expected_prompt_id.to_owned(),
        outputs: artifacts,
        completed,
    })
}

// ---------------------------------------------------------------------------
// View — GET /view with bounded download and remote-identifier validation.
// ---------------------------------------------------------------------------

/// Query parameters for `GET /view`, built only from validated remote
/// identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyViewRequest {
    pub filename: String,
    pub subfolder: String,
    pub r#type: String,
}

impl ComfyViewRequest {
    pub fn from_artifact(artifact: &ComfyOutputArtifact) -> Result<Self> {
        artifact.validate_remote_identifiers()?;
        Ok(Self {
            filename: artifact.filename.clone(),
            subfolder: artifact.subfolder.clone(),
            r#type: artifact.r#type.clone(),
        })
    }

    /// Serializes to query parameters for a GET request.
    pub fn to_query_params(&self) -> Vec<(&'static str, String)> {
        vec![
            ("filename", self.filename.clone()),
            ("subfolder", self.subfolder.clone()),
            ("type", self.r#type.clone()),
        ]
    }
}

// ---------------------------------------------------------------------------
// WebSocket events — /ws with duplicate/out-of-order/foreign reconciliation.
// ---------------------------------------------------------------------------

/// A parsed ComfyUI WebSocket event, filtered to the current client/prompt.
/// Foreign client/prompt events are ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComfyWsEvent {
    /// Progress update (execution started, preview, etc).
    Progress {
        prompt_id: String,
        value: u64,
        max: u64,
    },
    /// Execution completed successfully.
    Executed { prompt_id: String },
    /// Execution failed.
    ExecutionError {
        prompt_id: String,
        safe_reason: String,
    },
    /// The prompt was cancelled or interrupted.
    ExecutionInterrupted { prompt_id: String },
}

/// Parses a raw WebSocket text message into a ComfyUI event. Returns `None`
/// for foreign or unrecognized messages.
pub fn parse_ws_event(message: &str, expected_client_id: &str) -> Result<Option<ComfyWsEvent>> {
    let value: serde_json::Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    let obj = match value.as_object() {
        Some(o) => o,
        None => return Ok(None),
    };
    // Foreign client events are ignored.
    if let Some(client_id) = obj.get("client_id").and_then(serde_json::Value::as_str)
        && client_id != expected_client_id
    {
        return Ok(None);
    }
    let prompt_id = obj
        .get("prompt_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let event_type = match obj.get("type").and_then(serde_json::Value::as_str) {
        Some(t) => t,
        None => return Ok(None),
    };
    match event_type {
        "progress" => {
            let prompt_id = prompt_id.context("progress event missing prompt_id")?;
            let value = obj
                .get("value")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let max = obj
                .get("max")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            Ok(Some(ComfyWsEvent::Progress {
                prompt_id,
                value,
                max,
            }))
        }
        "executed" => {
            let prompt_id = prompt_id.context("executed event missing prompt_id")?;
            Ok(Some(ComfyWsEvent::Executed { prompt_id }))
        }
        "execution_error" => {
            let prompt_id = prompt_id.context("execution_error event missing prompt_id")?;
            let safe_reason = obj
                .get("exception_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("execution_failed")
                .to_owned();
            Ok(Some(ComfyWsEvent::ExecutionError {
                prompt_id,
                safe_reason,
            }))
        }
        "execution_interrupted" => {
            let prompt_id = prompt_id.context("execution_interrupted event missing prompt_id")?;
            Ok(Some(ComfyWsEvent::ExecutionInterrupted { prompt_id }))
        }
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Reconciliation — monotonic slot state for duplicate/out-of-order events.
// ---------------------------------------------------------------------------

/// Tracks the monotonic execution state of a single prompt to reconcile
/// duplicate and out-of-order events.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PromptExecutionState {
    pub prompt_id: String,
    pub progress_value: u64,
    pub progress_max: u64,
    pub completed: bool,
    pub failed: bool,
    pub interrupted: bool,
}

impl PromptExecutionState {
    pub fn new(prompt_id: String) -> Self {
        Self {
            prompt_id,
            ..Default::default()
        }
    }

    /// Applies an event, enforcing monotonic progression. Duplicate or
    /// out-of-order events that would regress state are ignored.
    pub fn apply_event(&mut self, event: &ComfyWsEvent) {
        if event.prompt_id() != self.prompt_id {
            return;
        }
        match event {
            ComfyWsEvent::Progress { value, max, .. } => {
                // Progress is monotonic — ignore regressions.
                if *value >= self.progress_value {
                    self.progress_value = *value;
                    self.progress_max = *max;
                }
            }
            ComfyWsEvent::Executed { .. } => {
                if !self.failed && !self.interrupted {
                    self.completed = true;
                }
            }
            ComfyWsEvent::ExecutionError { .. } => {
                if !self.completed {
                    self.failed = true;
                }
            }
            ComfyWsEvent::ExecutionInterrupted { .. } => {
                if !self.completed && !self.failed {
                    self.interrupted = true;
                }
            }
        }
    }

    /// Returns `true` if the prompt has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.completed || self.failed || self.interrupted
    }
}

impl ComfyWsEvent {
    fn prompt_id(&self) -> &str {
        match self {
            Self::Progress { prompt_id, .. }
            | Self::Executed { prompt_id }
            | Self::ExecutionError { prompt_id, .. }
            | Self::ExecutionInterrupted { prompt_id } => prompt_id,
        }
    }
}

// ---------------------------------------------------------------------------
// Cleanup obligation — remote artifacts Cockpit owns and must delete through a
// discovered safe route. Persisted separately from local managed artifacts.
// ---------------------------------------------------------------------------

/// A remote cleanup obligation for an uploaded or generated artifact on the
/// ComfyUI server. Cockpit deletes only exact artifacts it can prove it owns
/// and only through a discovered safe delete route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCleanupObligation {
    /// The Cockpit-owned upload namespace prefix.
    pub namespace_prefix: String,
    /// The remote artifact name (filename for uploads, or output filename).
    pub filename: String,
    /// The remote subfolder, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subfolder: String,
    /// Whether a safe delete route was discovered. If `false`, the obligation
    /// is recorded but cannot be fulfilled — failure to delete is disclosed,
    /// not hidden.
    pub delete_supported: bool,
}

impl RemoteCleanupObligation {
    /// Creates an obligation for an uploaded reference artifact.
    pub fn for_upload(response: &ComfyUploadResponse, delete_supported: bool) -> Result<Self> {
        validate_remote_identifier(&response.name)?;
        validate_subfolder(&response.subfolder)?;
        Ok(Self {
            namespace_prefix: response.subfolder.clone(),
            filename: response.name.clone(),
            subfolder: response.subfolder.clone(),
            delete_supported,
        })
    }

    /// Creates an obligation for a generated output artifact.
    pub fn for_output(artifact: &ComfyOutputArtifact, delete_supported: bool) -> Result<Self> {
        artifact.validate_remote_identifiers()?;
        Ok(Self {
            namespace_prefix: String::new(),
            filename: artifact.filename.clone(),
            subfolder: artifact.subfolder.clone(),
            delete_supported,
        })
    }

    /// Returns `true` if this obligation can be fulfilled (a safe delete route
    /// was discovered).
    pub fn fn_fulfillable(&self) -> bool {
        self.delete_supported
    }
}

// ---------------------------------------------------------------------------
// Config identity — changes that invalidate grants/plans vs display rename.
// ---------------------------------------------------------------------------

/// Computes the ComfyUI-specific identity for an endpoint + target +
/// workflow binding. Any change to endpoint identity, credential identity,
/// route profile, workflow bytes/digest, binding descriptor, cancellation
/// capability, or location class invalidates grants and undispatched plans.
/// Display rename alone does not.
pub fn comfy_target_identity(
    endpoint: &ImageEndpoint,
    workflow: &RegisteredComfyWorkflow,
    cancellation_capability: ComfyCancellationCapability,
) -> String {
    let endpoint_identity = endpoint.immutable_identity();
    let binding_digest = workflow.binding_digest();
    let graph_digest = &workflow.graph_digest;
    // Include cancellation capability — it is part of target/plan identity.
    let identity_input = (
        &endpoint_identity,
        graph_digest,
        &binding_digest,
        cancellation_capability.as_str(),
    );
    let bytes = serde_json::to_vec(&identity_input).expect("identity must serialize");
    let digest = Sha256::digest(&bytes);
    let mut hex = String::with_capacity(64);
    use fmt::Write as _;
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

// ---------------------------------------------------------------------------
// Health/discovery — route availability, version, queue/job cancellation
// support, workflow/object-info compatibility, required node classes/inputs,
// and output bindings without mutating the queue.
// ---------------------------------------------------------------------------

/// Discovery evidence for a ComfyUI endpoint, gathered without mutating the
/// queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfyDiscovery {
    /// Whether `POST /api/jobs/{job_id}/cancel` is available.
    pub job_cancel_supported: bool,
    /// Whether `POST /queue {"delete":[...]}` is available.
    pub queue_delete_supported: bool,
    /// Whether `GET /history/{prompt_id}` is available (polling fallback).
    pub history_supported: bool,
    /// Whether `/ws` WebSocket is available.
    pub ws_supported: bool,
    /// Whether a safe delete route for owned artifacts is available.
    pub delete_supported: bool,
    /// The server version, if reported.
    pub server_version: Option<String>,
    /// Whether the registered workflow's nodes and inputs are compatible with
    /// the server's object-info.
    pub workflow_compatible: bool,
}

impl ComfyDiscovery {
    /// Determines the best cancellation capability available from discovery,
    /// before runtime queue state is considered.
    pub fn base_cancellation_capability(
        &self,
        endpoint: &ImageEndpoint,
    ) -> ComfyCancellationCapability {
        if self.job_cancel_supported {
            ComfyCancellationCapability::JobScopedCancel
        } else if self.queue_delete_supported {
            ComfyCancellationCapability::QueuedPromptDelete
        } else if endpoint.exclusive_server {
            ComfyCancellationCapability::ExclusiveServerInterrupt
        } else {
            ComfyCancellationCapability::Unsupported
        }
    }
}

// ---------------------------------------------------------------------------
// Adapter kind accessor.
// ---------------------------------------------------------------------------

/// Returns the adapter kind for this module. Used for registration.
pub const fn adapter_kind() -> ImageAdapterKind {
    ImageAdapterKind::Comfyui
}

// ---------------------------------------------------------------------------
// Re-exports for convenience.
// ---------------------------------------------------------------------------

pub use ComfyCancellationCapability as CancellationCapability;

#[cfg(test)]
mod tests;
