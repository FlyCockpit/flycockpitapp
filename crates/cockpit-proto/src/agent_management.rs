//! Safe daemon-owned agent management wire types.
//!
//! Agent files are authority-bearing configuration. Clients receive only a
//! render/edit projection plus an opaque revision and send typed mutations
//! back to the daemon; paths and parsed core implementation types never cross
//! the wire.

use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEditorLease {
    pub lease_id: String,
    pub expires_at_unix_ms: i64,
    pub snapshot: AgentEditSnapshot,
}
