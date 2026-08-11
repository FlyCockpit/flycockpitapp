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
//!   query, never body, never path, never model-supplied.
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
    SealedParamSpec,
};
use super::identity::{SealedDescription, SealedProjectKey};

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
    /// A fixed query parameter name. The credential value is placed in this
    /// query parameter.
    Query { param_name: String },
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
            Self::Query { param_name } => {
                if param_name.is_empty() || param_name.len() > 64 {
                    bail!("credential query param name must be 1..64 bytes");
                }
                if !param_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
                {
                    bail!("credential query param name must be alphanumeric with '_' or '.'");
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
        }
    }

    /// The fixed projection id for this kind.
    pub fn projection(&self) -> SealedProjectionId {
        match self {
            Self::Https { projection, .. } => *projection,
        }
    }

    /// The origin allowlist for this kind, if HTTPS.
    pub fn origins(&self) -> Option<&HttpsOriginAllowlist> {
        match self {
            Self::Https { origins, .. } => Some(origins),
        }
    }

    /// The credential placement for this kind, if HTTPS.
    pub fn credential_placement(&self) -> Option<&HttpsCredentialPlacement> {
        match self {
            Self::Https {
                credential_placement,
                ..
            } => Some(credential_placement),
        }
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

impl SealedActionInstanceSummary {
    fn from_snapshot(snap: &SealedActionSnapshot) -> Self {
        let kind_tag = match &snap.kind {
            SealedActionKind::Https { .. } => "https",
        };
        Self {
            action_id: snap.action_id.clone(),
            revision: snap.revision,
            kind_tag: kind_tag.to_string(),
            description: snap.description.clone(),
            project_key: snap.project_key.clone(),
            enabled: snap.enabled,
            created_at_ms: snap.created_at_ms,
            retired_at_ms: snap.retired_at_ms,
        }
    }
}

/// What the Owner supplies to create a sealed action instance.
#[derive(Debug, Clone)]
pub struct CreateSealedAction {
    pub action_id: String,
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

/// The Owner-facing action-instance store.
///
/// Every method demands [`OwnerAuthority`]. Agents and remote clients cannot
/// create, revise, retire, or list action instances, because they cannot
/// obtain that token.
///
/// This is an in-memory store for the daemon's process lifetime. Persistence
/// to SQLite is the store layer's responsibility; this module compiles and
/// holds the immutable snapshots.
#[derive(Debug, Default)]
pub struct SealedActionDirectory {
    snapshots: std::sync::Mutex<BTreeMap<String, SealedActionSnapshot>>,
}

impl SealedActionDirectory {
    /// Create a new empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a sealed action instance. Compiles the kind into an immutable
    /// snapshot and persists it.
    pub fn create(
        &self,
        _owner: OwnerAuthority,
        request: CreateSealedAction,
        now_ms: i64,
    ) -> Result<SealedActionInstanceSummary> {
        request.kind.validate()?;
        // Compile the descriptor to validate the action id and revision.
        request
            .kind
            .compile_descriptor(&request.action_id, 1, request.description.as_str())?;

        let snapshot = SealedActionSnapshot {
            action_id: request.action_id.clone(),
            revision: 1,
            kind: request.kind,
            description: request.description.as_str().to_string(),
            project_key: request.project_key.as_str().to_string(),
            enabled: true,
            created_at_ms: now_ms,
            retired_at_ms: None,
        };

        let mut snapshots = self.snapshots.lock().expect("directory mutex");
        if snapshots.contains_key(&request.action_id) {
            bail!("sealed action `{}` already exists", request.action_id);
        }
        snapshots.insert(request.action_id.clone(), snapshot.clone());
        Ok(SealedActionInstanceSummary::from_snapshot(&snapshot))
    }

    /// Revise a sealed action instance. Creates a new revision, atomically
    /// retires the old one, and returns the new summary.
    ///
    /// In a full implementation, this revokes dependent grants before the
    /// snapshot changes. Here, the grant revocation is the caller's
    /// responsibility (the store layer's `revoke_action_grant`).
    pub fn revise(
        &self,
        _owner: OwnerAuthority,
        request: ReviseSealedAction,
        _now_ms: i64,
    ) -> Result<SealedActionInstanceSummary> {
        let (action_id, new_description, new_enabled) = match &request {
            ReviseSealedAction::Description {
                action_id,
                description,
            } => (
                action_id.clone(),
                Some(description.as_str().to_string()),
                None,
            ),
            ReviseSealedAction::Enabled { action_id, enabled } => {
                (action_id.clone(), None, Some(*enabled))
            }
        };

        let mut snapshots = self.snapshots.lock().expect("directory mutex");
        let existing = snapshots
            .get(&action_id)
            .context("sealed action does not exist")?
            .clone();
        if existing.retired_at_ms.is_some() {
            bail!("cannot revise a retired sealed action");
        }

        let new_revision = existing.revision + 1;
        let description = new_description.unwrap_or_else(|| existing.description.clone());
        let enabled = new_enabled.unwrap_or(existing.enabled);

        // Compile the new descriptor to validate the revision.
        existing
            .kind
            .compile_descriptor(&action_id, new_revision, &description)?;

        let snapshot = SealedActionSnapshot {
            action_id: action_id.clone(),
            revision: new_revision,
            kind: existing.kind.clone(),
            description,
            project_key: existing.project_key.clone(),
            enabled,
            created_at_ms: existing.created_at_ms,
            retired_at_ms: None,
        };
        snapshots.insert(action_id.clone(), snapshot.clone());
        Ok(SealedActionInstanceSummary::from_snapshot(&snapshot))
    }

    /// Retire a sealed action instance. Revokes dependent grants (caller's
    /// responsibility) and marks the snapshot as retired.
    pub fn retire(&self, _owner: OwnerAuthority, action_id: &str, now_ms: i64) -> Result<bool> {
        let mut snapshots = self.snapshots.lock().expect("directory mutex");
        let existing = snapshots
            .get(action_id)
            .context("sealed action does not exist")?;
        if existing.retired_at_ms.is_some() {
            return Ok(false);
        }
        let mut snapshot = existing.clone();
        snapshot.retired_at_ms = Some(now_ms);
        snapshot.enabled = false;
        snapshots.insert(action_id.to_string(), snapshot);
        Ok(true)
    }

    /// List all action instances. Owner-only.
    pub fn list(&self, _owner: OwnerAuthority) -> Result<Vec<SealedActionInstanceSummary>> {
        let snapshots = self.snapshots.lock().expect("directory mutex");
        Ok(snapshots
            .values()
            .map(SealedActionInstanceSummary::from_snapshot)
            .collect())
    }

    /// Get one action instance's summary. Owner-only.
    pub fn summary(
        &self,
        _owner: OwnerAuthority,
        action_id: &str,
    ) -> Result<Option<SealedActionInstanceSummary>> {
        let snapshots = self.snapshots.lock().expect("directory mutex");
        Ok(snapshots
            .get(action_id)
            .map(SealedActionInstanceSummary::from_snapshot))
    }

    /// Get one action instance's snapshot. Owner-only. Used by the runtime to
    /// compile the descriptor for the registry.
    pub fn snapshot(&self, action_id: &str) -> Option<SealedActionSnapshot> {
        self.snapshots
            .lock()
            .expect("directory mutex")
            .get(action_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests;
