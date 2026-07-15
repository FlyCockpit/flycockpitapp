//! Persisted session and interrupt wire shapes used by DB rows.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMessage {
    pub seq: i64,
    pub ts_ms: i64,
    pub role: MessageRole,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    pub project_root: String,
    pub project_id: String,
    pub started_at: i64,
    pub last_active_at: i64,
    pub turns: u32,
    pub active_agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_principal: Option<String>,
    #[serde(default)]
    pub shared_with_collaborators: bool,
    #[serde(default)]
    pub fork_count: u32,
    #[serde(default)]
    pub descendant_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_viewed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_activity_at: Option<i64>,
    #[serde(default)]
    pub open_interrupts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity_state: Option<SessionActivityState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<i64>,
    #[serde(default)]
    pub pin_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionActivityState {
    Parked,
    PendingQuestion,
    Interrupted,
    InferenceInProgress,
    ToolRunning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", content = "data")]
pub enum InterruptQuestion {
    Single {
        prompt: String,
        options: Vec<InterruptOption>,
        #[serde(default = "default_allow_freetext")]
        allow_freetext: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_detail: Option<Box<CommandDetail>>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        permission: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox_escalation: Option<SandboxEscalation>,
    },
    Multi {
        prompt: String,
        options: Vec<InterruptOption>,
        #[serde(default = "default_allow_freetext")]
        allow_freetext: bool,
    },
    Freetext {
        prompt: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        masked: bool,
    },
}

fn default_allow_freetext() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptOption {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub secondary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandDetail {
    pub full_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight: Option<CharSpan>,
    pub step: u32,
    pub step_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remembered_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_content: Option<WriteContentPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_tool_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offered_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_cap: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteContentPreview {
    pub content: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dynamic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharSpan {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxEscalation {
    pub confined_exit: i32,
    pub confined_stderr: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggested_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_access: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptQuestionSet {
    pub questions: Vec<InterruptQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterruptDecisionLine {
    pub prompt: String,
    pub answer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterruptDecision {
    pub permission: bool,
    pub cancelled: bool,
    pub lines: Vec<InterruptDecisionLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", content = "data")]
pub enum ResolveResponse {
    Single { selected_id: String },
    Multi { selected_ids: Vec<String> },
    Freetext { text: String },
    Batch { responses: Vec<ResolveResponse> },
    Cancel,
}

impl ResolveResponse {
    pub fn into_batch(self, n: usize) -> Vec<ResolveResponse> {
        match self {
            ResolveResponse::Batch { responses } => responses,
            ResolveResponse::Cancel => std::iter::repeat_n(ResolveResponse::Cancel, n).collect(),
            other => vec![other],
        }
    }
}
