//! Persisted session and interrupt wire shapes used by DB rows.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
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

/// Existing approval-store taxonomy. Interrupts carry this exact class so
/// noninteractive clients can grant a class once without parsing display copy
/// or inventing a parallel vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    Command,
    Path,
    McpTool,
    Harness,
}

impl GrantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Path => "path",
            Self::McpTool => "mcp_tool",
            Self::Harness => "harness",
        }
    }
}

impl std::str::FromStr for GrantKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "command" => Ok(Self::Command),
            "path" => Ok(Self::Path),
            "mcp_tool" => Ok(Self::McpTool),
            "harness" => Ok(Self::Harness),
            other => Err(format!(
                "unknown approval class `{other}`; expected command, path, mcp_tool, or harness"
            )),
        }
    }
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
        approval_class: Option<GrantKind>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial: Option<SandboxDenialReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxDenialReport {
    pub confidence: SandboxDenialConfidence,
    pub evidence: Vec<SandboxDenialEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDenialConfidence {
    High,
    Possible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxDenialEvidence {
    WriteOutsideAllowlist {
        path: String,
    },
    ReadOutsideAllowlist {
        path: String,
    },
    StderrPermissionMarker,
    Unknown {
        kind: String,
        data: Option<Value>,
        raw: Option<Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", content = "data")]
enum KnownSandboxDenialEvidence {
    WriteOutsideAllowlist { path: String },
    ReadOutsideAllowlist { path: String },
    StderrPermissionMarker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawSandboxDenialEvidence {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

impl Serialize for SandboxDenialEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::WriteOutsideAllowlist { path } => {
                KnownSandboxDenialEvidence::WriteOutsideAllowlist { path: path.clone() }
                    .serialize(serializer)
            }
            Self::ReadOutsideAllowlist { path } => {
                KnownSandboxDenialEvidence::ReadOutsideAllowlist { path: path.clone() }
                    .serialize(serializer)
            }
            Self::StderrPermissionMarker => {
                KnownSandboxDenialEvidence::StderrPermissionMarker.serialize(serializer)
            }
            Self::Unknown { kind, data, raw } => {
                if let Some(raw) = raw {
                    raw.serialize(serializer)
                } else {
                    RawSandboxDenialEvidence {
                        kind: kind.clone(),
                        data: data.clone(),
                    }
                    .serialize(serializer)
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for SandboxDenialEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if let Ok(known) = serde_json::from_value::<KnownSandboxDenialEvidence>(value.clone()) {
            return Ok(match known {
                KnownSandboxDenialEvidence::WriteOutsideAllowlist { path } => {
                    Self::WriteOutsideAllowlist { path }
                }
                KnownSandboxDenialEvidence::ReadOutsideAllowlist { path } => {
                    Self::ReadOutsideAllowlist { path }
                }
                KnownSandboxDenialEvidence::StderrPermissionMarker => Self::StderrPermissionMarker,
            });
        }

        let raw = serde_json::from_value::<RawSandboxDenialEvidence>(value.clone())
            .map_err(serde::de::Error::custom)?;
        Ok(Self::Unknown {
            kind: raw.kind,
            data: raw.data,
            raw: Some(value),
        })
    }
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

#[cfg(test)]
mod tests {
    use super::{
        SandboxDenialConfidence, SandboxDenialEvidence, SandboxDenialReport, SandboxEscalation,
    };
    use serde_json::{Value, json};

    #[test]
    fn sandbox_denial_wire_report_round_trips() {
        let report = SandboxDenialReport {
            confidence: SandboxDenialConfidence::High,
            evidence: vec![
                SandboxDenialEvidence::WriteOutsideAllowlist {
                    path: "/var/cache/tool".into(),
                },
                SandboxDenialEvidence::StderrPermissionMarker,
            ],
        };

        let value = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(
            value,
            json!({
                "confidence": "high",
                "evidence": [
                    {
                        "kind": "write_outside_allowlist",
                        "data": { "path": "/var/cache/tool" }
                    },
                    { "kind": "stderr_permission_marker" }
                ]
            })
        );

        let back: SandboxDenialReport = serde_json::from_value(value).expect("deserialize report");
        assert_eq!(back, report);
    }

    #[test]
    fn sandbox_denial_wire_absent_key_round_trips() {
        let escalation = SandboxEscalation {
            confined_exit: 101,
            confined_stderr: "permission denied".into(),
            suggested_paths: Vec::new(),
            suggested_access: None,
            denial: None,
        };

        let value = serde_json::to_value(&escalation).expect("serialize escalation");
        assert!(
            value.get("denial").is_none(),
            "None denial should omit the key: {value}"
        );

        let legacy = json!({
            "confined_exit": 101,
            "confined_stderr": "permission denied"
        });
        let back: SandboxEscalation =
            serde_json::from_value(legacy).expect("deserialize legacy escalation");
        assert!(back.denial.is_none());
    }

    #[test]
    fn sandbox_denial_wire_unknown_evidence_forward_open() {
        let value = json!({
            "kind": "network_denied",
            "data": { "host": "x" }
        });

        let evidence: SandboxDenialEvidence =
            serde_json::from_value(value.clone()).expect("deserialize unknown evidence");
        assert_eq!(
            evidence,
            SandboxDenialEvidence::Unknown {
                kind: "network_denied".into(),
                data: Some(json!({ "host": "x" })),
                raw: Some(value.clone()),
            }
        );

        let back: Value = serde_json::to_value(&evidence).expect("serialize unknown evidence");
        assert_eq!(back, value);

        let future_value = json!({
            "kind": "network_denied",
            "data": null,
            "source": "future_sandbox"
        });
        let future_evidence: SandboxDenialEvidence =
            serde_json::from_value(future_value.clone()).expect("deserialize future evidence");
        let future_back: Value =
            serde_json::to_value(&future_evidence).expect("serialize future evidence");
        assert_eq!(future_back, future_value);
    }
}
