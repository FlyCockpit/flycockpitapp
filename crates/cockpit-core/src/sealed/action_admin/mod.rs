//! Immutable action-instance administration: the closed schema compiler,
//! snapshot persistence, and revision lifecycle.
//!
//! Action instances are immutable `{action_id UUID, revision, kind, safe
//! description, canonical project scope, enabled, created/retired timestamps,
//! schema}` records. Every action is project-scoped; Global values may be
//! granted only to an action instance in a canonical trusted project, never a
//! global action. Updating creates a new revision, atomically retires the old
//! one, and revokes dependent grants before the snapshot changes; deletion
//! likewise revokes first.
//!
//! # What this module owns
//!
//! * [`SealedActionKind`] — the closed enum of built-in action kinds. Each
//!   variant is a fixed Rust struct, not config data.
//! * [`HttpsOrigin`] — a validated `https` origin. No `http`, no wildcard, no
//!   IP literal, no user-info, no query, no fragment.
//! * [`HttpsOriginAllowlist`] — a bounded, validated set of origins.
//! * [`HttpsCredentialPlacement`] — fixed credential placement: header or
//!   whole body, never path and never model-supplied.
//! * command argument/environment and file sinks whose argv, environment key,
//!   destination, persistence, and consumer are immutable Owner-owned data.
//! * [`SealedProjectionId`] — the fixed projection enum selected by
//!   `fixed-projection-id`. Each variant maps to a fixed set of safe response
//!   fields.
//! * [`SealedActionSnapshot`] — the immutable persisted snapshot of one
//!   action instance. Every field is compiled to a fixed runtime snapshot.
//! * [`SealedParamSpecJson`] — the JSON-serializable parameter spec, for
//!   persistence. Closed: no free-form text parameter.
//! * [`SealedActionDirectory`] — the Owner-facing action store: create,
//!   revise, retire, list. Every method demands [`OwnerAuthority`].
//! * [`CreateSealedAction`] / [`ReviseSealedAction`] — the Owner request
//!   types.
//! * [`SealedActionInstanceSummary`] — safe metadata for one action instance.
//!
//! # Invariants
//!
//! * Built-in action kinds are closed Rust enums. No agent/project/plugin/
//!   environment/remote/model input can supply a URL, header, template,
//!   credential location, or arbitrary projection schema.
//! * HTTPS kinds contain fixed validated `https` origin allowlists, fixed
//!   credential placement, typed bounded non-secret parameters, host-owned
//!   request template, redirect policy deny, fixed projection enum selected
//!   by `fixed-projection-id`, and timeout/size limits.
//! * Local commands never invoke a shell. Files are 0600, git-guarded, and
//!   ephemeral by default; persistence is an explicit Owner-approved downgrade.
//! * Updating creates a new revision, atomically retires the old one, and
//!   revokes dependent grants before the snapshot changes.
//! * Deletion (retire) revokes dependent grants first.
//! * No default action instance is created from project config or discovered
//!   CLI state; all instances are explicit Owner records.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::action::{
    OwnerAuthority, SealedActionDescriptor, SealedActionId, SealedActionRevision, SealedCompletion,
    SealedHostAction, SealedParamSpec, SealedParams,
};
use super::compartment::SealedLiteralHandle;
use super::identity::{SealedDescription, SealedKnowledgeBaseId, SealedProjectKey};

/// Maximum number of origins in one HTTPS action's allowlist.
pub const HTTPS_MAX_ORIGINS: usize = 8;

/// Maximum single origin length, in bytes.
pub const HTTPS_MAX_ORIGIN_BYTES: usize = 256;

/// Maximum HTTPS response body size, in bytes.
pub const HTTPS_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Fixed HTTPS request timeout, in milliseconds.
pub const HTTPS_TIMEOUT_MS: u64 = 15_000;

/// Maximum number of parameters one action may declare.
pub const MAX_SEALED_ACTION_PARAMS: usize = 8;

/// A validated `https` origin. No `http`, no wildcard, no IP literal, no
/// user-info, no query, no fragment, no path. The origin is
/// `https://host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HttpsOrigin {
    host: String,
    port: Option<u16>,
}

impl HttpsOrigin {
    /// Parse and validate an `https://host[:port]` origin.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > HTTPS_MAX_ORIGIN_BYTES {
            bail!("origin exceeds {HTTPS_MAX_ORIGIN_BYTES} bytes");
        }
        let rest = raw
            .strip_prefix("https://")
            .with_context(|| "origin must start with `https://`")?;
        if rest.is_empty() {
            bail!("origin host must not be empty");
        }
        if rest.contains('@') {
            bail!("origin must not contain user-info");
        }
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            bail!("origin must not contain a path, query, or fragment");
        }
        if rest.starts_with('[') {
            bail!("origin must not be an IP literal");
        }
        let octets: Vec<&str> = rest.split('.').collect();
        if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
            bail!("origin must not be an IPv4 literal");
        }

        let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
            let port: u16 = p.parse().context("origin port must be a valid u16")?;
            (h.to_string(), Some(port))
        } else {
            (rest.to_string(), None)
        };
        if host.is_empty() {
            bail!("origin host must not be empty");
        }
        if !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        {
            bail!("origin host must be lowercase alphanumeric with '.' or '-'");
        }
        // Reject obviously non-public hostnames so an allowlisted origin cannot
        // name loopback or an internal service directly. Origins are Owner-authored
        // from a closed catalog, so this is defense in depth; a *public* name that
        // resolves to a private address (DNS rebinding to a metadata service) is a
        // residual that resolve-and-pin would close — a heavier follow-up.
        if host == "localhost" {
            bail!("origin host must not be localhost");
        }
        if !host.contains('.') {
            bail!("origin host must be a fully-qualified domain name");
        }
        if [".local", ".internal", ".localhost"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
        {
            bail!("origin host must not use a private or internal TLD");
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Render as `https://host[:port]`.
    pub fn as_str(&self) -> String {
        match self.port {
            Some(p) => format!("https://{}:{}", self.host, p),
            None => format!("https://{}", self.host),
        }
    }
}

impl fmt::Display for HttpsOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// A bounded, validated set of HTTPS origins.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HttpsOriginAllowlist {
    origins: Vec<HttpsOrigin>,
}

impl HttpsOriginAllowlist {
    /// Build an allowlist from raw origin strings. Validates each and bounds
    /// the set to [`HTTPS_MAX_ORIGINS`].
    pub fn from_raw(raws: &[&str]) -> Result<Self> {
        if raws.is_empty() {
            bail!("HTTPS action must declare at least one origin");
        }
        if raws.len() > HTTPS_MAX_ORIGINS {
            bail!("HTTPS action declares more than {HTTPS_MAX_ORIGINS} origins");
        }
        let mut origins = Vec::with_capacity(raws.len());
        let mut seen = std::collections::BTreeSet::new();
        for raw in raws {
            let origin = HttpsOrigin::parse(raw)?;
            if !seen.insert(origin.as_str()) {
                bail!("HTTPS action declares a duplicate origin");
            }
            origins.push(origin);
        }
        Ok(Self { origins })
    }

    pub fn len(&self) -> usize {
        self.origins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &HttpsOrigin> {
        self.origins.iter()
    }

    /// Check whether a given origin string matches one in the allowlist.
    pub fn matches(&self, origin_str: &str) -> bool {
        self.origins.iter().any(|o| o.as_str() == origin_str)
    }

    /// Get the origin at the given index. Used by the catalog selector.
    pub fn get(&self, index: usize) -> Option<&HttpsOrigin> {
        self.origins.get(index)
    }
}

/// Where a credential is placed in an HTTPS request. Fixed at compile time;
/// never model-supplied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpsCredentialPlacement {
    /// A fixed header name. The credential value is placed in this header.
    Header { header_name: String },
    /// The complete request body. The sealed literal is sent as the body and
    /// is never interpolated into model-authored data.
    Body { content_type: String },
}

impl HttpsCredentialPlacement {
    /// Validate the credential placement.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Header { header_name } => {
                if header_name.is_empty() || header_name.len() > 64 {
                    bail!("credential header name must be 1..64 bytes");
                }
                if !header_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    bail!("credential header name must be alphanumeric with '-' or '_'");
                }
            }
            Self::Body { content_type } => {
                if content_type.is_empty() || content_type.len() > 128 {
                    bail!("credential body content type must be 1..128 bytes");
                }
                if !content_type
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'-' | b'.'))
                {
                    bail!("credential body content type contains invalid bytes");
                }
            }
        }
        Ok(())
    }
}

/// The fixed projection enum. Selected by `fixed-projection-id` at compile
/// time. Each variant maps to a fixed set of safe response fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedProjectionId {
    /// No fields beyond the fixed completion.
    None,
    /// `status` field: the HTTP status code as a safe string.
    HttpStatus,
    /// `status` and `ok` fields.
    HttpStatusAndOk,
}

impl SealedProjectionId {
    /// Parse a fixed projection id.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "none" => Ok(Self::None),
            "http_status" => Ok(Self::HttpStatus),
            "http_status_and_ok" => Ok(Self::HttpStatusAndOk),
            _ => bail!("unknown fixed projection id: `{raw}`"),
        }
    }

    /// The fixed completion fields this projection renders.
    pub fn completion_fields(self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::None => vec![("outcome", "completed")],
            Self::HttpStatus => vec![("outcome", "completed"), ("status", "redacted")],
            Self::HttpStatusAndOk => vec![
                ("outcome", "completed"),
                ("status", "redacted"),
                ("ok", "redacted"),
            ],
        }
    }

    /// The string id of this projection.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HttpStatus => "http_status",
            Self::HttpStatusAndOk => "http_status_and_ok",
        }
    }
}

/// The JSON-serializable parameter spec, for persistence. Closed: no
/// free-form text parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SealedParamSpecJson {
    Choice { allowed: Vec<String> },
    BoundedInteger { min: i64, max: i64 },
    Flag,
}

impl SealedParamSpecJson {
    /// Convert to a runtime [`SealedParamSpec`].
    pub fn to_spec(&self) -> SealedParamSpec {
        match self {
            Self::Choice { allowed } => SealedParamSpec::Choice {
                allowed: allowed.clone(),
            },
            Self::BoundedInteger { min, max } => SealedParamSpec::BoundedInteger {
                min: *min,
                max: *max,
            },
            Self::Flag => SealedParamSpec::Flag,
        }
    }

    /// Convert from a runtime [`SealedParamSpec`].
    pub fn from_spec(spec: &SealedParamSpec) -> Self {
        match spec {
            SealedParamSpec::Choice { allowed } => Self::Choice {
                allowed: allowed.clone(),
            },
            SealedParamSpec::BoundedInteger { min, max } => Self::BoundedInteger {
                min: *min,
                max: *max,
            },
            SealedParamSpec::Flag => Self::Flag,
        }
    }
}

/// The closed enum of built-in action kinds. Each variant is a fixed Rust
/// struct, not config data. No agent/project/plugin/environment/remote/model
/// input can add a variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealedActionKind {
    /// An HTTPS action with a fixed origin allowlist, credential placement,
    /// bounded parameters, request template, redirect-deny policy, fixed
    /// projection, and timeout/size limits.
    Https {
        origins: HttpsOriginAllowlist,
        credential_placement: HttpsCredentialPlacement,
        path_template: String,
        projection: SealedProjectionId,
        parameters: BTreeMap<String, SealedParamSpecJson>,
    },
    /// A fixed local command with the literal injected into either one argv
    /// placeholder or one environment variable. No shell is involved.
    Command {
        argv_template: Vec<String>,
        injection: local_executor::CommandInjection,
        parameters: BTreeMap<String, SealedParamSpecJson>,
    },
    /// Materialize to an Owner-pinned destination and optionally run a fixed
    /// consumer. Ephemeral mode requires a consumer and deletes on every exit.
    File {
        destination: local_executor::FileDestination,
        persistence: local_executor::FilePersistence,
        consumer_argv: Vec<String>,
    },
    /// A local-only custody transfer to exactly one immutable KB attachment.
    /// It has no outbound destination and no model-supplied parameters.
    KnowledgeBaseCopy {
        knowledge_base_id: SealedKnowledgeBaseId,
    },
}

impl SealedActionKind {
    /// Validate the kind specification.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Https {
                origins,
                credential_placement,
                path_template,
                projection: _,
                parameters,
            } => {
                if origins.is_empty() {
                    bail!("HTTPS action must declare at least one origin");
                }
                if origins.len() > HTTPS_MAX_ORIGINS {
                    bail!("HTTPS action declares more than {HTTPS_MAX_ORIGINS} origins");
                }
                // Re-parse every origin through the validating constructor. A
                // derived `Deserialize` bypasses `HttpsOrigin::parse`, so a
                // persisted (or otherwise deserialized) origin could carry an
                // `http`, wildcard, user-info, or IP-literal host that the parse
                // path rejects; round-tripping here makes `validate` fail closed
                // on such a corrupt origin instead of trusting the raw fields.
                for origin in origins.iter() {
                    HttpsOrigin::parse(&origin.as_str())
                        .context("persisted HTTPS origin fails origin validation")?;
                }
                credential_placement.validate()?;
                if !path_template.starts_with('/') {
                    bail!("HTTPS action path template must start with '/'");
                }
                if path_template.contains("://") {
                    bail!("HTTPS action path template must not contain a scheme");
                }
                if path_template.len() > 256 {
                    bail!("HTTPS action path template must be at most 256 bytes");
                }
                if parameters.len() > MAX_SEALED_ACTION_PARAMS {
                    bail!("HTTPS action declares more than {MAX_SEALED_ACTION_PARAMS} parameters");
                }
                // Validate each parameter spec.
                for (name, spec) in parameters {
                    if name.is_empty() || name.len() > 48 {
                        bail!("parameter name must be 1..48 bytes");
                    }
                    if !name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        bail!("parameter name must be lowercase alphanumeric with '_'");
                    }
                    match spec {
                        SealedParamSpecJson::Choice { allowed } => {
                            if allowed.is_empty() {
                                bail!("parameter `{name}` declares an empty choice set");
                            }
                            if allowed.len() > 32 {
                                bail!("parameter `{name}` declares more than 32 choices");
                            }
                            for choice in allowed {
                                if choice.len() > 256 {
                                    bail!("parameter `{name}` declares a choice beyond 256 bytes");
                                }
                            }
                        }
                        SealedParamSpecJson::BoundedInteger { min, max } => {
                            if min > max {
                                bail!("parameter `{name}` has an empty integer band");
                            }
                            let span = max.checked_sub(*min).unwrap_or(i64::MAX);
                            if span > 4_096 {
                                bail!(
                                    "parameter `{name}` integer band exceeds 4096; a wider \
                                     band could carry a packed destination"
                                );
                            }
                        }
                        SealedParamSpecJson::Flag => {}
                    }
                }
                Ok(())
            }
            Self::KnowledgeBaseCopy { knowledge_base_id } => {
                if knowledge_base_id.as_uuid().is_nil() {
                    bail!("knowledge-base copy action has a nil attachment id");
                }
                Ok(())
            }
            Self::Command {
                argv_template,
                injection,
                parameters,
            } => local_executor::validate_command_kind(argv_template, injection, parameters),
            Self::File {
                destination,
                persistence,
                consumer_argv,
            } => local_executor::validate_file_kind(destination, *persistence, consumer_argv),
        }
    }

    /// Compile this kind into an immutable action descriptor. This is the
    /// snapshot compiler: every persisted field is compiled to a fixed
    /// runtime snapshot.
    pub fn compile_descriptor(
        &self,
        action_id: &str,
        revision: u32,
        summary: &str,
    ) -> Result<SealedActionDescriptor> {
        let action_id = SealedActionId::parse(action_id)?;
        let revision = SealedActionRevision::new(revision)?;
        match self {
            Self::Https {
                projection,
                parameters,
                ..
            } => {
                let completion = SealedCompletion::fixed(projection.completion_fields());
                let params: BTreeMap<String, SealedParamSpec> = parameters
                    .iter()
                    .map(|(name, spec)| (name.clone(), spec.to_spec()))
                    .collect();
                let descriptor = SealedActionDescriptor {
                    action_id,
                    revision,
                    summary: summary.to_string(),
                    parameters: params,
                    completion,
                    response_after_ms: HTTPS_TIMEOUT_MS,
                };
                descriptor.validate()?;
                Ok(descriptor)
            }
            Self::KnowledgeBaseCopy { .. } => {
                let descriptor = SealedActionDescriptor {
                    action_id,
                    revision,
                    summary: summary.to_string(),
                    parameters: BTreeMap::new(),
                    completion: SealedCompletion::fixed(std::iter::empty::<(String, String)>()),
                    response_after_ms: HTTPS_TIMEOUT_MS,
                };
                descriptor.validate()?;
                Ok(descriptor)
            }
            Self::Command { parameters, .. } => {
                let descriptor = SealedActionDescriptor {
                    action_id,
                    revision,
                    summary: summary.to_string(),
                    parameters: parameters
                        .iter()
                        .map(|(name, spec)| (name.clone(), spec.to_spec()))
                        .collect(),
                    completion: SealedCompletion::fixed([("outcome", "completed")]),
                    response_after_ms: HTTPS_TIMEOUT_MS,
                };
                descriptor.validate()?;
                Ok(descriptor)
            }
            Self::File { .. } => {
                let descriptor = SealedActionDescriptor {
                    action_id,
                    revision,
                    summary: summary.to_string(),
                    parameters: BTreeMap::new(),
                    completion: SealedCompletion::fixed([("outcome", "completed")]),
                    response_after_ms: HTTPS_TIMEOUT_MS,
                };
                descriptor.validate()?;
                Ok(descriptor)
            }
        }
    }

    /// The fixed projection id for this kind.
    pub fn projection(&self) -> SealedProjectionId {
        match self {
            Self::Https { projection, .. } => *projection,
            Self::KnowledgeBaseCopy { .. } => SealedProjectionId::None,
            Self::Command { .. } | Self::File { .. } => SealedProjectionId::None,
        }
    }

    /// The origin allowlist for this kind, if HTTPS.
    pub fn origins(&self) -> Option<&HttpsOriginAllowlist> {
        match self {
            Self::Https { origins, .. } => Some(origins),
            Self::KnowledgeBaseCopy { .. } => None,
            Self::Command { .. } | Self::File { .. } => None,
        }
    }

    /// The credential placement for this kind, if HTTPS.
    pub fn credential_placement(&self) -> Option<&HttpsCredentialPlacement> {
        match self {
            Self::Https {
                credential_placement,
                ..
            } => Some(credential_placement),
            Self::KnowledgeBaseCopy { .. } => None,
            Self::Command { .. } | Self::File { .. } => None,
        }
    }
}

/// Closed local executor for a KB-copy capability. `invoke` is deliberately
/// unreachable for production use: the sealed runtime consumes this kind only
/// through `copy_to_knowledge_base`, where it writes to the bound attachment.
#[derive(Debug)]
struct KnowledgeBaseCopyAction {
    descriptor: SealedActionDescriptor,
    knowledge_base_id: SealedKnowledgeBaseId,
}

impl KnowledgeBaseCopyAction {
    fn from_snapshot(snapshot: &SealedActionSnapshot) -> Result<Self> {
        let SealedActionKind::KnowledgeBaseCopy { knowledge_base_id } = &snapshot.kind else {
            bail!("knowledge-base copy executor requires a copy action snapshot");
        };
        Ok(Self {
            descriptor: snapshot.kind.compile_descriptor(
                &snapshot.action_id,
                snapshot.revision,
                &snapshot.description,
            )?,
            knowledge_base_id: knowledge_base_id.clone(),
        })
    }
}

#[async_trait::async_trait]
impl SealedHostAction for KnowledgeBaseCopyAction {
    fn descriptor(&self) -> &SealedActionDescriptor {
        &self.descriptor
    }

    fn knowledge_base_copy_target(&self) -> Option<&SealedKnowledgeBaseId> {
        Some(&self.knowledge_base_id)
    }

    fn sink_kind(&self) -> &'static str {
        "file"
    }

    async fn invoke(
        &self,
        _literal: SealedLiteralHandle<'_>,
        _params: &SealedParams,
    ) -> Result<()> {
        bail!("knowledge-base copy actions may only run through the sealed copy runtime")
    }
}

/// The immutable persisted snapshot of one action instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedActionSnapshot {
    pub action_id: String,
    pub revision: u32,
    pub kind: SealedActionKind,
    pub description: String,
    pub project_key: String,
    pub enabled: bool,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

/// Safe metadata for one action instance. This is the Owner inventory
/// projection: action id, revision, kind tag, safe description, project scope,
/// enabled, and timestamps. It carries no literal, no credential, and no
/// request template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedActionInstanceSummary {
    pub action_id: String,
    pub revision: u32,
    pub kind_tag: String,
    pub description: String,
    pub project_key: String,
    pub enabled: bool,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

/// What the Owner supplies to create a sealed action instance.
///
/// There is deliberately no `action_id` field: the daemon mints a fresh UUID
/// for every create, so no caller (owner RPC input included) can choose or
/// collide with the persisted id (AC12).
#[derive(Debug, Clone)]
pub struct CreateSealedAction {
    pub kind: SealedActionKind,
    pub description: SealedDescription,
    pub project_key: SealedProjectKey,
}

/// What the Owner supplies to revise a sealed action instance.
#[derive(Debug, Clone)]
pub enum ReviseSealedAction {
    /// Change the safe description. Creates a new revision.
    Description {
        action_id: String,
        description: SealedDescription,
    },
    /// Enable or disable. Creates a new revision.
    Enabled { action_id: String, enabled: bool },
}

impl ReviseSealedAction {
    /// The action id this revision targets.
    pub fn action_id(&self) -> &str {
        match self {
            Self::Description { action_id, .. } | Self::Enabled { action_id, .. } => action_id,
        }
    }
}

/// The Owner-facing action-instance store, backed by SQLite.
///
/// Every method demands [`OwnerAuthority`]. Agents and remote clients cannot
/// create, revise, retire, or list action instances, because they cannot
/// obtain that token.
///
/// Snapshots are durable (`sealed_action_instances`), so instances survive a
/// daemon restart. The daemon mints every `action_id` (a fresh UUID — no caller
/// chooses it). A revise or retire revokes the dependent grants in the SAME
/// transaction that mutates the snapshot row, so a crash can never leave a
/// retired/revised action with a live grant; a revise additionally fences on the
/// prior revision to reject a concurrent lost-update.
#[derive(Clone)]
pub struct SealedActionDirectory {
    db: cockpit_db::db::Db,
}

impl std::fmt::Debug for SealedActionDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedActionDirectory")
            .finish_non_exhaustive()
    }
}

impl SealedActionDirectory {
    /// Build a directory over a database handle.
    pub fn new(db: cockpit_db::db::Db) -> Self {
        Self { db }
    }

    /// Create a sealed action instance. Compiles + validates the kind, mints a
    /// fresh daemon-owned `action_id` (AC12), and persists the immutable
    /// snapshot at revision 1.
    pub async fn create(
        &self,
        _owner: OwnerAuthority,
        request: CreateSealedAction,
        now_ms: i64,
    ) -> Result<SealedActionInstanceSummary> {
        request.kind.validate()?;
        // The daemon mints the id; no caller input can choose or collide with it.
        let action_id = uuid::Uuid::new_v4().to_string();
        // Compile the descriptor to validate the id + revision before persisting.
        request
            .kind
            .compile_descriptor(&action_id, 1, request.description.as_str())?;
        let kind_json =
            serde_json::to_string(&request.kind).context("serializing sealed action kind")?;
        self.db
            .insert_sealed_action_instance(
                cockpit_db::db::sealed_actions::NewSealedActionInstance {
                    action_id: action_id.clone(),
                    revision: 1,
                    kind_json,
                    description: request.description.as_str().to_string(),
                    project_key: request.project_key.as_str().to_string(),
                    created_at_ms: now_ms,
                },
            )
            .await?;
        let row = self
            .db
            .sealed_action_instance(action_id)
            .await?
            .context("created sealed action instance not found after insert")?;
        summary_from_row(&row)
    }

    /// Revise a sealed action instance's description or enabled flag, creating a
    /// new revision. Revokes every dependent grant in the SAME transaction that
    /// writes the new snapshot, and fences on the prior revision so a concurrent
    /// revise cannot silently overwrite (AC4).
    pub async fn revise(
        &self,
        _owner: OwnerAuthority,
        request: ReviseSealedAction,
        now_ms: i64,
    ) -> Result<SealedActionInstanceSummary> {
        let action_id = request.action_id().to_string();
        let existing = self
            .db
            .sealed_action_instance(action_id.clone())
            .await?
            .context("sealed action does not exist")?;
        if existing.retired_at_ms.is_some() {
            bail!("cannot revise a retired sealed action");
        }
        let description = match &request {
            ReviseSealedAction::Description { description, .. } => description.as_str().to_string(),
            ReviseSealedAction::Enabled { .. } => existing.description.clone(),
        };
        let enabled = match &request {
            ReviseSealedAction::Enabled { enabled, .. } => *enabled,
            ReviseSealedAction::Description { .. } => existing.enabled,
        };
        let expected_prev = existing.revision;
        let new_revision = existing.revision + 1;
        // Revalidate the persisted kind and compile the new revision (id +
        // revision bounds) before the tx; a corrupt stored kind fails closed.
        let kind = decode_validated_kind(&existing.kind_json)?;
        kind.compile_descriptor(&action_id, checked_revision(new_revision)?, &description)?;
        let kind_json = existing.kind_json.clone();
        // One transaction: revoke dependent grants BEFORE the snapshot changes,
        // then compare-and-swap the revision.
        let tx_action_id = action_id.clone();
        let row = self
            .db
            .transaction(move |conn| {
                cockpit_db::db::sealed_actions::revoke_action_grants_conn(
                    conn,
                    &tx_action_id,
                    now_ms,
                )?;
                cockpit_db::db::sealed_actions::revise_action_instance_conn(
                    conn,
                    &tx_action_id,
                    expected_prev,
                    new_revision,
                    &kind_json,
                    &description,
                    enabled,
                )
            })
            .await?;
        summary_from_row(&row)
    }

    /// Retire a sealed action instance. Revokes every dependent grant in the
    /// SAME transaction that stamps the row retired, so no grant outlives the
    /// retired snapshot becoming visible (AC13). Returns `true` when this call
    /// retired a previously-live instance, `false` when it was already retired.
    pub async fn retire(
        &self,
        _owner: OwnerAuthority,
        action_id: &str,
        now_ms: i64,
    ) -> Result<bool> {
        let action_id = action_id.to_string();
        self.db
            .transaction(move |conn| {
                cockpit_db::db::sealed_actions::revoke_action_grants_conn(
                    conn, &action_id, now_ms,
                )?;
                cockpit_db::db::sealed_actions::retire_action_instance_conn(
                    conn, &action_id, now_ms,
                )
            })
            .await
    }

    /// List all action instances. Owner-only.
    pub async fn list(&self, _owner: OwnerAuthority) -> Result<Vec<SealedActionInstanceSummary>> {
        let rows = self.db.list_sealed_action_instances().await?;
        rows.iter().map(summary_from_row).collect()
    }

    /// Get one action instance's summary. Owner-only.
    pub async fn summary(
        &self,
        _owner: OwnerAuthority,
        action_id: &str,
    ) -> Result<Option<SealedActionInstanceSummary>> {
        match self
            .db
            .sealed_action_instance(action_id.to_string())
            .await?
        {
            Some(row) => Ok(Some(summary_from_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Get one action instance's snapshot. Owner-only. Used by the runtime to
    /// compile the descriptor for the registry.
    pub async fn snapshot(&self, action_id: &str) -> Result<Option<SealedActionSnapshot>> {
        match self
            .db
            .sealed_action_instance(action_id.to_string())
            .await?
        {
            Some(row) => Ok(Some(snapshot_from_row(&row)?)),
            None => Ok(None),
        }
    }
}

/// Decode + REVALIDATE a persisted action kind. Derived `Deserialize` bypasses
/// the validating constructors (`HttpsOrigin::parse`, `SealedActionKind::validate`),
/// so a semantically-invalid-but-serde-valid stored `kind_json` (e.g. an
/// IP-literal origin, an `http` origin, or a bad path template written by DB
/// tampering or a future schema) would otherwise be accepted on read. Every read
/// path revalidates here so a corrupt snapshot fails closed rather than reaching
/// the executor (defense in depth for the increment-3 egress path).
fn decode_validated_kind(kind_json: &str) -> Result<SealedActionKind> {
    let kind: SealedActionKind =
        serde_json::from_str(kind_json).context("decoding persisted sealed action kind")?;
    kind.validate()
        .context("persisted sealed action kind failed revalidation")?;
    Ok(kind)
}

/// A persisted revision must fit the `u32` the runtime uses; an out-of-range
/// value is corruption and fails closed rather than being clamped.
fn checked_revision(revision: i64) -> Result<u32> {
    u32::try_from(revision).context("persisted sealed action revision is out of range")
}

/// Project a persisted action-instance row into its safe Owner summary,
/// decoding + revalidating the kind from the stored JSON.
fn summary_from_row(
    row: &cockpit_db::db::sealed_actions::SealedActionInstanceRow,
) -> Result<SealedActionInstanceSummary> {
    let kind = decode_validated_kind(&row.kind_json)?;
    let kind_tag = match kind {
        SealedActionKind::Https { .. } => "https",
        SealedActionKind::KnowledgeBaseCopy { .. } => "knowledge_base_copy",
        SealedActionKind::Command { injection, .. } => injection.sink_kind(),
        SealedActionKind::File { .. } => "file",
    };
    Ok(SealedActionInstanceSummary {
        action_id: row.action_id.clone(),
        revision: checked_revision(row.revision)?,
        kind_tag: kind_tag.to_string(),
        description: row.description.clone(),
        project_key: row.project_key.clone(),
        enabled: row.enabled,
        created_at_ms: row.created_at_ms,
        retired_at_ms: row.retired_at_ms,
    })
}

/// Reconstruct the full immutable snapshot from a persisted row, revalidating the
/// kind so a corrupt snapshot never reaches a consumer.
fn snapshot_from_row(
    row: &cockpit_db::db::sealed_actions::SealedActionInstanceRow,
) -> Result<SealedActionSnapshot> {
    Ok(SealedActionSnapshot {
        action_id: row.action_id.clone(),
        revision: checked_revision(row.revision)?,
        kind: decode_validated_kind(&row.kind_json)?,
        description: row.description.clone(),
        project_key: row.project_key.clone(),
        enabled: row.enabled,
        created_at_ms: row.created_at_ms,
        retired_at_ms: row.retired_at_ms,
    })
}

pub mod executor;
pub mod local_executor;

/// The shared production HTTPS transport (a redirect-disabled, proxy-ignoring
/// reqwest client). Cheap to clone; safe to share across every action and
/// session. It carries no action definitions, credentials, or proxy config — only
/// a connection/DNS pool — so a process-global is correct (nothing to clobber or
/// cross-resolve between databases). Fallible so a client-build failure denies
/// (via [`build_live_registry`]) rather than panicking the daemon.
pub fn shared_https_transport() -> Result<std::sync::Arc<dyn executor::HttpsTransport>> {
    static TRANSPORT: std::sync::OnceLock<std::sync::Arc<dyn executor::HttpsTransport>> =
        std::sync::OnceLock::new();
    if let Some(transport) = TRANSPORT.get() {
        return Ok(transport.clone());
    }
    let transport: std::sync::Arc<dyn executor::HttpsTransport> =
        std::sync::Arc::new(executor::ReqwestHttpsTransport::new()?);
    // Cache the first successful build; a losing race just drops its own client.
    Ok(TRANSPORT.get_or_init(|| transport).clone())
}

/// Build the live sealed-action registry from the persisted snapshots of ONE
/// project.
///
/// The registry is a pure function of `sealed_action_instances`: every live +
/// enabled snapshot **for `project_key`** compiles into an executable
/// [`executor::HttpsSealedAction`] over the shared transport. Rebuilding on read
/// — rather than caching an install-once (`OnceLock`) or shared-mutable registry
/// — keeps it always live and per-database isolated: two daemons over two
/// databases never see each other's actions, and there is no process-global
/// mutable registry to race or clobber.
///
/// Scoping to the caller's `project_key` is a security boundary, not a
/// convenience: an action is compiled for a fixed project endpoint, so a session
/// in a different project must never resolve it (which would send that session's
/// literal to another project's destination). A snapshot that fails to revalidate
/// or compile is skipped (so only its own uses deny) rather than denying every
/// action.
pub async fn build_live_registry(
    db: &cockpit_db::db::Db,
    project_key: &str,
) -> Result<std::sync::Arc<super::action::SealedActionRegistry>> {
    let owner = super::action::OwnerAuthority::for_owner_request();
    let transport = shared_https_transport()?;
    let rows = db.list_sealed_action_instances().await?;
    let mut builder = super::action::SealedActionRegistry::builder(owner);
    for row in rows {
        if row.retired_at_ms.is_some() || !row.enabled {
            continue;
        }
        // Project boundary: only this project's actions are resolvable here.
        if row.project_key != project_key {
            continue;
        }
        let Ok(snapshot) = snapshot_from_row(&row) else {
            continue;
        };
        match &snapshot.kind {
            SealedActionKind::Https { .. } => {
                let Ok(action) =
                    executor::HttpsSealedAction::from_snapshot(&snapshot, transport.clone())
                else {
                    continue;
                };
                builder = builder.with_action(std::sync::Arc::new(action))?;
            }
            SealedActionKind::KnowledgeBaseCopy { .. } => {
                let Ok(action) = KnowledgeBaseCopyAction::from_snapshot(&snapshot) else {
                    continue;
                };
                builder = builder.with_action(std::sync::Arc::new(action))?;
            }
            SealedActionKind::Command { .. } => {
                let Ok(action) = local_executor::CommandSealedAction::from_snapshot(&snapshot)
                else {
                    continue;
                };
                builder = builder.with_action(std::sync::Arc::new(action))?;
            }
            SealedActionKind::File { .. } => {
                let Ok(action) = local_executor::FileSealedAction::from_snapshot(&snapshot) else {
                    continue;
                };
                builder = builder.with_action(std::sync::Arc::new(action))?;
            }
        }
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests;
