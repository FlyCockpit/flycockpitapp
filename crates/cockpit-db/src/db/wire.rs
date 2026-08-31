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
    /// Immutable daemon-owned entry setup copied from the durable session row.
    pub session_entry_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    pub project_root: String,
    pub project_id: String,
    pub started_at_unix_ms: i64,
    pub last_active_at_unix_ms: i64,
    pub turns: u32,
    pub active_agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<Uuid>,
    /// Message anchor in `parent_session_id`, when this is a fork. Exposing
    /// it with the durable lineage projection lets clients navigate back to
    /// the originating message after the initial fork response is gone.
    pub fork_point_turn_id: Option<String>,
    /// Durable first-class assistant-thread discriminator. A child session
    /// is not a thread merely because it has a parent.
    pub is_assistant_thread: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_principal: Option<String>,
    #[serde(default)]
    pub shared_with_collaborators: bool,
    #[serde(default)]
    pub fork_count: u32,
    #[serde(default)]
    pub descendant_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_viewed_at_unix_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_activity_at_unix_ms: Option<i64>,
    #[serde(default)]
    pub open_interrupts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity_state: Option<SessionActivityState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at_unix_ms: Option<i64>,
    #[serde(default)]
    pub pin_count: u32,
    /// Undelivered assistant-inbox work for this main session. Notify-only
    /// rows are visible here too, but never count toward agent work budgets.
    #[serde(default)]
    pub assistant_inbox_unread: u32,
    /// Raising thread for the newest unread item; clients use this durable
    /// backlink to drill into the source conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assistant_inbox_latest_source_session_id: Option<Uuid>,
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
    /// Typed image-generation authorization-review projection, present only when
    /// the pending approval is an image-generation plan. Carries redacted plan
    /// facts (digest, cost, budget disposition, output location) — never a
    /// credential, provider URL, workflow JSON, or host path. `None` for every
    /// non-image approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_plan_review: Option<ImagePlanReview>,
}

/// A redacted budget disposition for one spend scope within an image plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageBudgetDisposition {
    /// The spend scope this disposition applies to (`request`/`session`/`project`).
    pub scope: String,
    /// A stable, non-secret disposition label (e.g. `within_budget`,
    /// `blocked_unconfigured`, `exceeds_budget`).
    pub disposition: String,
}

/// A typed image-generation authorization-review model rendered by the standalone
/// approval overlay. It replaces the earlier generic `full_command` string with
/// dedicated, redacted plan fields.
///
/// SECURITY / INERT-DISPATCH: several fields (`plan_digest`, `conservative_cost_usd_micros`)
/// can only be derived from a LIVE dispatch, which is currently inert upstream
/// (the runtime adapter/destination map ships empty). Those fields fail closed —
/// `plan_digest` stays `None` and `cost_unknown` stays `true` until a real
/// dispatch populates them — rather than fabricating a plausible value. Fields
/// derivable from the plan projection / config (location classes, offered scopes,
/// budget disposition, fanout/slots) are populated when available.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImagePlanReview {
    /// The plan digest, when a live dispatch has produced one. `None` = not yet
    /// available (dispatch inert); the overlay renders a fail-closed placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<String>,
    /// Destination location classes for this plan (e.g. `local`, `remote_hosted`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_location_classes: Vec<String>,
    /// The conservative maximum cost in USD micros, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conservative_cost_usd_micros: Option<u64>,
    /// True when the conservative cost cannot be bounded (renders `cost_unknown`).
    #[serde(default)]
    pub cost_unknown: bool,
    /// Per-scope budget dispositions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budget_dispositions: Vec<ImageBudgetDisposition>,
    /// The output host location class (never a raw path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_location_class: Option<String>,
    /// A redacted reference-egress summary (counts / classes, never URLs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_egress_summary: Option<String>,
    /// Plan fanout (number of targets), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout: Option<u32>,
    /// Plan slot count, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slots: Option<u32>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
