//! Safe daemon-owned agent management wire types.
//!
//! Agent files are authority-bearing configuration. Clients receive only a
//! render/edit projection plus an opaque revision and send typed mutations
//! back to the daemon; paths and parsed core implementation types never cross
//! the wire.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub const MAX_AGENT_NAME_BYTES: usize = 128;
pub const MAX_AGENT_MARKDOWN_BYTES: usize = 256 * 1024;
pub const MAX_AGENT_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_ASSISTANT_HOME_BYTES: usize = 16 * 1024;
pub const MAX_ASSISTANT_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_ASSISTANT_DIAGNOSTIC_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEntryKind {
    Builtin,
    Custom,
}

/// Origin of the effective definition. Mutations are deliberately limited to
/// the selected workspace layer; an effective definition from another layer
/// must never be silently shadowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSourceLayer {
    Embedded,
    Workspace,
    OtherConfigLayer,
    ConfiguredDirectory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEditTarget {
    Workspace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInventoryEntry {
    pub name: String,
    pub kind: AgentEntryKind,
    pub overridden: bool,
    pub description: Option<String>,
    pub model: Option<String>,
    pub valid: bool,
    pub diagnostic: Option<String>,
    /// Exact effective-source ownership used to bind later actions.
    pub source_layer: AgentSourceLayer,
    /// Opaque daemon-minted source occurrence identity. It contains no path
    /// or locator material and is meaningful only with `revision`.
    pub source_identity: String,
    /// Exact revision of the effective source and workspace target state.
    pub revision: String,
    pub editable: bool,
    /// Digest of the exact redacted presentation fields in this response.
    /// `revision` remains an opaque authority CAS token.
    pub projection_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEditSnapshot {
    pub name: String,
    pub kind: AgentEntryKind,
    pub overridden: bool,
    /// Exact authored markdown when the effective source is a file. Embedded
    /// definitions use their canonical rendering here.
    pub markdown: String,
    /// Canonical rendering is a preview only and is never substituted for the
    /// exact authored bytes during a partial mutation.
    pub canonical_preview: String,
    pub source_layer: AgentSourceLayer,
    /// Opaque identity of the exact source selected by layered resolution.
    pub source_identity: String,
    pub edit_target: AgentEditTarget,
    /// Opaque content/identity revision. Clients must return it on mutation.
    pub revision: String,
    pub goal_supervision_json: Option<String>,
    pub editable: bool,
    pub supports_goal_supervision: bool,
    /// Digest of the exact redacted presentation fields in this response.
    pub projection_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mutation", rename_all = "snake_case")]
pub enum AgentMutation {
    EjectBuiltin {
        name: String,
    },
    SaveDefinition {
        name: String,
        markdown: String,
    },
    /// Create a workspace definition only when the target was absent in the
    /// snapshot used to mint `expected_revision`.
    CreateDefinition {
        name: String,
        markdown: String,
    },
    DeleteCustom {
        name: String,
    },
    ResetBuiltin {
        name: String,
    },
    ResetAllBuiltins,
    SaveGoalSupervision {
        name: String,
        patch: GoalSupervisionPatch,
    },
}

/// Typed partial patch for the fields exposed by the goal-settings pane.
/// `None` leaves a field unchanged; `Some(None)` explicitly inherits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GoalSupervisionPatch {
    pub cold_skeptic_count: Option<Option<usize>>,
    pub cold_skeptic_model: Option<Option<String>>,
    pub max_verification_attempts: Option<Option<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMutationResult {
    pub changed: bool,
    pub affected: u32,
    #[serde(deserialize_with = "deserialize_present_option")]
    pub snapshot: Option<AgentEditSnapshot>,
    pub config_generation: u64,
    /// Present for inventory-wide mutations such as reset-all and bound to the
    /// post-commit inventory returned by a subsequent refresh.
    #[serde(deserialize_with = "deserialize_present_option")]
    pub inventory_revision: Option<String>,
    /// Exact document or inventory revision consumed by the daemon. Creation
    /// is the only mutation that legitimately has no prior revision.
    #[serde(deserialize_with = "deserialize_present_option")]
    pub consumed_revision: Option<String>,
    /// Present only on the completion response for this exact editor lease.
    #[serde(deserialize_with = "deserialize_present_option")]
    pub completed_lease_id: Option<String>,
    /// Whether the daemon could reconcile the post-commit projection. A
    /// refresh-needed result is still a committed mutation and must never be
    /// retried as though the write failed.
    pub outcome: AgentMutationOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentMutationOutcome {
    Reconciled,
    CommittedRefreshNeeded { warning: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEditorLease {
    pub lease_id: String,
    pub expires_at_unix_ms: i64,
    pub snapshot: AgentEditSnapshot,
}

pub fn validate_agent_mutation_envelope(
    result: &AgentMutationResult,
    expected_consumed_revision: Option<&str>,
    expected_completed_lease_id: Option<&str>,
    inventory_wide: bool,
) -> Result<(), &'static str> {
    let token = |value: &str| crate::is_opaque_authority_token(value);
    if result
        .consumed_revision
        .as_deref()
        .is_some_and(|value| !token(value))
        || result
            .inventory_revision
            .as_deref()
            .is_some_and(|value| !token(value))
    {
        return Err("agent mutation contains a malformed authority token");
    }
    if result.consumed_revision.as_deref() != expected_consumed_revision {
        return Err("agent mutation consumed the wrong revision");
    }
    if result.completed_lease_id.as_deref() != expected_completed_lease_id {
        return Err("agent mutation completion is bound to the wrong editor lease");
    }
    if inventory_wide != result.inventory_revision.is_some() {
        return Err("agent mutation inventory revision has the wrong scope");
    }
    if !inventory_wide && result.affected > 1 {
        return Err("single-agent mutation affected multiple definitions");
    }
    if let AgentMutationOutcome::CommittedRefreshNeeded { warning } = &result.outcome
        && (warning.trim().is_empty() || warning.len() > MAX_AGENT_METADATA_BYTES)
    {
        return Err("agent mutation refresh warning is invalid");
    }
    if !inventory_wide
        && matches!(
            &result.outcome,
            AgentMutationOutcome::CommittedRefreshNeeded { .. }
        )
    {
        return Err("single-agent mutation cannot require an inventory refresh");
    }
    Ok(())
}

pub fn validate_goal_supervision_projection(
    prior_json: Option<&str>,
    patch: &GoalSupervisionPatch,
    result_json: Option<&str>,
) -> Result<(), &'static str> {
    fn object(
        raw: Option<&str>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, &'static str> {
        match raw {
            None => Ok(serde_json::Map::new()),
            Some(raw) => serde_json::from_str::<serde_json::Value>(raw)
                .map_err(|_| "goal supervision JSON is malformed")?
                .as_object()
                .cloned()
                .ok_or("goal supervision JSON is not an object"),
        }
    }
    let mut expected = object(prior_json)?;
    let mut apply = |key: &str, value: Option<serde_json::Value>| {
        if let Some(value) = value {
            expected.insert(key.to_string(), value);
        } else {
            expected.remove(key);
        }
    };
    if let Some(value) = &patch.cold_skeptic_count {
        apply("coldSkepticCount", (*value).map(serde_json::Value::from));
    }
    if let Some(value) = &patch.cold_skeptic_model {
        apply(
            "coldSkepticModel",
            value.clone().map(serde_json::Value::from),
        );
    }
    if let Some(value) = &patch.max_verification_attempts {
        apply(
            "maxVerificationAttempts",
            (*value).map(serde_json::Value::from),
        );
    }
    if object(result_json)? != expected {
        return Err("goal supervision mutation changed fields outside its exact patch");
    }
    Ok(())
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
}

pub fn validate_agent_edit_snapshot(snapshot: &AgentEditSnapshot) -> Result<(), &'static str> {
    fn lower_hex_digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
    if snapshot.name.is_empty()
        || snapshot.name.len() > MAX_AGENT_NAME_BYTES
        || snapshot.markdown.len() > MAX_AGENT_MARKDOWN_BYTES
        || snapshot.canonical_preview.len() > MAX_AGENT_MARKDOWN_BYTES
        || !lower_hex_digest(&snapshot.source_identity)
        || !lower_hex_digest(&snapshot.revision)
        || !lower_hex_digest(&snapshot.projection_digest)
        || snapshot
            .goal_supervision_json
            .as_ref()
            .is_some_and(|value| value.len() > MAX_AGENT_METADATA_BYTES)
    {
        return Err("agent snapshot identity is missing");
    }
    if snapshot.projection_digest != agent_edit_projection_digest(snapshot) {
        return Err("agent snapshot projection digest is invalid");
    }
    if snapshot
        .goal_supervision_json
        .as_ref()
        .is_some_and(|value| serde_json::from_str::<serde_json::Value>(value).is_err())
    {
        return Err("agent goal supervision projection is invalid");
    }
    if snapshot.overridden != (snapshot.source_layer != AgentSourceLayer::Embedded)
        || snapshot.editable != (snapshot.source_layer == AgentSourceLayer::Workspace)
    {
        return Err("agent snapshot ownership flags are incoherent");
    }
    Ok(())
}

pub fn agent_inventory_entry_projection_digest(entry: &AgentInventoryEntry) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cockpit-agent-inventory-projection-v1\0");
    for value in [
        Some(entry.name.as_str()),
        entry.description.as_deref(),
        entry.model.as_deref(),
        entry.diagnostic.as_deref(),
        Some(entry.source_identity.as_str()),
        Some(entry.revision.as_str()),
    ] {
        match value {
            Some(value) => {
                digest.update([1]);
                digest_field(&mut digest, value.as_bytes());
            }
            None => digest.update([0]),
        }
    }
    digest.update([
        entry.kind as u8,
        u8::from(entry.overridden),
        u8::from(entry.valid),
        entry.source_layer as u8,
        u8::from(entry.editable),
    ]);
    crate::hex_lower(digest.finalize())
}

pub fn agent_edit_projection_digest(snapshot: &AgentEditSnapshot) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cockpit-agent-edit-projection-v1\0");
    for value in [
        Some(snapshot.name.as_str()),
        Some(snapshot.markdown.as_str()),
        Some(snapshot.canonical_preview.as_str()),
        Some(snapshot.source_identity.as_str()),
        Some(snapshot.revision.as_str()),
        snapshot.goal_supervision_json.as_deref(),
    ] {
        match value {
            Some(value) => {
                digest.update([1]);
                digest_field(&mut digest, value.as_bytes());
            }
            None => digest.update([0]),
        }
    }
    digest.update([
        snapshot.kind as u8,
        u8::from(snapshot.overridden),
        snapshot.source_layer as u8,
        snapshot.edit_target as u8,
        u8::from(snapshot.editable),
        u8::from(snapshot.supports_goal_supervision),
    ]);
    crate::hex_lower(digest.finalize())
}

pub fn validate_agent_source_identity(
    snapshot: &AgentEditSnapshot,
    _project_root: &str,
) -> Result<(), &'static str> {
    validate_agent_edit_snapshot(snapshot)
}
