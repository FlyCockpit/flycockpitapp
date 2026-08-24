//! Safe daemon-owned agent management wire types.
//!
//! Agent files are authority-bearing configuration. Clients receive only a
//! render/edit projection plus an opaque revision and send typed mutations
//! back to the daemon; paths and parsed core implementation types never cross
//! the wire.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const MAX_AGENT_NAME_BYTES: usize = 128;
pub const MAX_AGENT_MARKDOWN_BYTES: usize = 256 * 1024;

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
    pub snapshot: Option<AgentEditSnapshot>,
    pub config_generation: u64,
    /// Present for inventory-wide mutations such as reset-all and bound to the
    /// post-commit inventory returned by a subsequent refresh.
    pub inventory_revision: Option<String>,
    /// Exact document or inventory revision consumed by the daemon. Creation
    /// is the only mutation that legitimately has no prior revision.
    #[serde(default)]
    pub consumed_revision: Option<String>,
    /// Present only on the completion response for this exact editor lease.
    #[serde(default)]
    pub completed_lease_id: Option<String>,
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

pub fn agent_inventory_revision(entries: &[AgentInventoryEntry]) -> String {
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let mut digest = Sha256::new();
    digest.update(b"cockpit-agent-inventory-revision-v1\0");
    for entry in ordered {
        for value in [
            entry.name.as_str(),
            entry.source_identity.as_str(),
            entry.revision.as_str(),
        ] {
            digest_field(&mut digest, value.as_bytes());
        }
        digest.update([
            entry.kind as u8,
            u8::from(entry.overridden),
            u8::from(entry.editable),
        ]);
    }
    format!("{:x}", digest.finalize())
}

pub fn agent_definition_revision(
    name: &str,
    source_layer: AgentSourceLayer,
    source_identity: &str,
    source_content_hash: &str,
    target_exists: bool,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cockpit-agent-definition-revision-v1\0");
    digest.update([source_layer as u8, u8::from(target_exists)]);
    for value in [name, source_identity, source_content_hash] {
        digest_field(&mut digest, value.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

pub fn validate_agent_edit_snapshot(snapshot: &AgentEditSnapshot) -> Result<(), &'static str> {
    if snapshot.name.is_empty()
        || snapshot.source_identity.len() != 64
        || !snapshot
            .source_identity
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("agent snapshot identity is missing");
    }
    let content_hash = format!("{:x}", Sha256::digest(snapshot.markdown.as_bytes()));
    let expected = agent_definition_revision(
        &snapshot.name,
        snapshot.source_layer,
        &snapshot.source_identity,
        &content_hash,
        snapshot.source_layer == AgentSourceLayer::Workspace,
    );
    if snapshot.revision != expected {
        return Err("agent snapshot revision is invalid");
    }
    if snapshot.overridden != (snapshot.source_layer != AgentSourceLayer::Embedded)
        || snapshot.editable != (snapshot.source_layer == AgentSourceLayer::Workspace)
    {
        return Err("agent snapshot ownership flags are incoherent");
    }
    Ok(())
}

pub fn validate_agent_source_identity(
    snapshot: &AgentEditSnapshot,
    _project_root: &str,
) -> Result<(), &'static str> {
    validate_agent_edit_snapshot(snapshot)
}
