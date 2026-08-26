//! Daemon-owned per-agent-node session-override DTOs (modes AC5/AC6/AC7).
//!
//! These carry the focused node's effective model/sandbox/mode/verification/
//! question settings, the daemon-classified allowed transitions, and the locked
//! reasons for inherited or host-bounded axes, plus the typed override a client
//! applies against an effective-settings revision. Every value, allowed set,
//! and locked reason is daemon-owned truth: the client renders it and never
//! infers an authority order. A session override may only preserve or reduce
//! the immutable profile/host authority envelope — it never raises authority.
//!
//! No provider profile handle, credential, filesystem path, or client-derived
//! compatibility guess crosses this boundary.

use serde::{Deserialize, Serialize};

use cockpit_config::config::extended::LlmMode;
use cockpit_config::config::sandbox_mode::SandboxMode;

pub const AGENT_EFFECTIVE_SETTINGS_DTO_VERSION: u32 = 1;

/// The focused agent node's daemon-resolved effective settings and the controls
/// a client may render for it. Scoped to one `agent_instance_id`; the daemon
/// derives every fact from the node's immutable profile/host envelope layered
/// with any accepted session override.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEffectiveSettingsV1 {
    pub dto_version: u32,
    pub session_id: String,
    pub agent_instance_id: String,
    /// Effective-settings revision for optimistic concurrency. A client echoes
    /// this exact value in [`crate::Request::ApplyAgentSessionOverride`]; a
    /// stale value is rejected without any state change, and each accepted
    /// apply increments and returns the next revision so competing
    /// old-revision requests become stale.
    pub override_revision: u64,
    /// True once the node is completed/failed/cancelled. No override may apply
    /// to a terminal node; controls render read-only.
    pub terminal: bool,
    pub sandbox: AgentSandboxControlV1,
    pub mode: AgentModeControlV1,
    pub verification: AgentVerificationControlV1,
    pub question: AgentQuestionControlV1,
}

/// Sandbox posture control. `allowed` is the daemon-classified non-escalating
/// transition set; `off` appears only when the envelope already permits it
/// (never to escape an `on`/`container` restriction).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSandboxControlV1 {
    pub effective: SandboxMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<SandboxMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_reason: Option<AgentControlLockedReasonV1>,
    /// A pending (not-yet-consumed) sandbox override staged for the node's next
    /// turn, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<SandboxMode>,
}

/// LLM-mode control. `allowed` holds only modes daemon policy classifies as
/// non-escalating for this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentModeControlV1 {
    pub effective: LlmMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<LlmMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_reason: Option<AgentControlLockedReasonV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<LlmMode>,
}

/// Verification control: the daemon-resolved disjoint effective regions. Each
/// region is a compiled `rule_match - earlier_matches` window; a reduction only
/// intersects or writes an explicit whole/remainder off mask for a region and
/// can never introduce a new verify region or delete an authored rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentVerificationControlV1 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<AgentVerificationRegionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentVerificationRegionV1 {
    /// Stable daemon-owned region identity a client references in a reduction.
    /// It is not an authored rule id and cannot request rule deletion.
    pub region_id: String,
    /// Daemon-owned human label. Carries no selector internals or authored
    /// predicate text.
    pub label: String,
    /// False once a whole-region off mask has been written for this session.
    pub enabled: bool,
    /// Whether an explicit off mask is offerable for the whole region.
    pub can_disable: bool,
    /// Whether a stricter selector / lower budget intersection is offerable.
    pub can_restrict: bool,
    /// A reduction is already staged for this region.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
}

/// Question-policy control. `effective` is absent when the resolved policy is
/// off or unset; an absent/off policy can never be enabled by a session
/// override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentQuestionControlV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective: Option<AgentQuestionEffectiveV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_reason: Option<AgentControlLockedReasonV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<AgentQuestionOverrideV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentQuestionEffectiveV1 {
    pub auto_answer_enabled: bool,
    pub required_decision_timeout_seconds: u32,
    /// Host resource ceiling. Requests above it are rejected, not clamped.
    pub host_ceiling_seconds: u32,
    /// Whether disabling auto-answer (the strictest reduction) is offerable.
    pub can_disable_auto_answer: bool,
    /// The largest timeout a client may request while auto-answer stays
    /// enabled. Lengthening up to this ceiling is a reduction; shortening below
    /// `required_decision_timeout_seconds` is forbidden.
    pub max_required_decision_timeout_seconds: u32,
}

/// Why an axis is not client-changeable. Closed set; carries no profile,
/// filesystem, or provider internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlLockedReasonV1 {
    /// The immutable profile fixes this axis; a session override cannot move it.
    InheritedFromProfile,
    /// A host policy bounds this axis; the daemon-unioned bound cannot be
    /// removed.
    HostPolicy,
    /// The node is terminal.
    Terminal,
}

/// One typed session-override field. Exactly one axis per apply request; the
/// daemon merges it into the node's pending override. Values reuse the
/// canonical config enums so the wire form cannot express a posture the engine
/// does not understand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "axis", rename_all = "snake_case")]
pub enum AgentSessionOverrideFieldV1 {
    /// Rebind the model slot to a hard-compatible local choice id drawn from
    /// the session-setup snapshot. The daemon re-validates compatibility; the
    /// client never sends a provider/profile handle.
    Model { slot_id: String, choice_id: String },
    /// Reduce sandbox posture to an envelope-permitted, non-escalating value.
    Sandbox { mode: SandboxMode },
    /// Set a non-escalating LLM mode for this node.
    Mode { mode: LlmMode },
    /// Reduce or disable verification for a daemon-resolved effective region.
    Verification { reduction: AgentVerificationReductionV1 },
    /// Apply a monotonic question-policy override.
    Question { policy: AgentQuestionOverrideV1 },
}

/// A verification reduction against one effective region. `Off` writes an
/// explicit whole-region off mask (never a rule deletion); `Restrict`
/// intersects the region with a stricter selector and/or lower budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentVerificationReductionV1 {
    Off {
        region_id: String,
    },
    Restrict {
        region_id: String,
        /// Additional selector tokens intersected into the region. Empty means
        /// budget-only narrowing.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        selector_intersection: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_candidates: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_total_tokens: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_estimated_cost_microusd: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_collection_millis: Option<u64>,
    },
}

/// A monotonic question-policy override. `Disable` is the strictest state;
/// `Reduce` keeps auto-answer enabled but lengthens the required decision
/// timeout (shortening is forbidden, over-ceiling is rejected).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentQuestionOverrideV1 {
    Disable,
    Reduce { required_decision_timeout_seconds: u32 },
}

/// Outcome of an [`crate::Request::ApplyAgentSessionOverride`]. A rejection or
/// stale revision leaves the node's pending override and revision unchanged;
/// `override_revision` always reports the daemon's current authoritative value
/// so the client can resync without a re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionOverrideStatusV1 {
    /// Merged into the pending override; `override_revision` is the new value.
    Applied,
    /// `expected_override_revision` did not match; no change.
    StaleRevision,
    /// No such node in the session.
    RejectedNotFound,
    /// The node is completed/failed/cancelled.
    RejectedTerminal,
    /// The field would raise authority above the immutable envelope.
    RejectedEscalation,
    /// The field is not applicable: model not hard-compatible, region unknown,
    /// question policy off/absent, or an over-ceiling timeout.
    RejectedIncompatible,
}

impl AgentSessionOverrideStatusV1 {
    pub fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn modes_session_setup_override_field_axis_tag_roundtrips() {
        // The `axis` tag distinguishes the five override axes on the wire.
        let sandbox = AgentSessionOverrideFieldV1::Sandbox {
            mode: SandboxMode::Container,
        };
        let json = serde_json::to_value(&sandbox).unwrap();
        assert_eq!(json["axis"], "sandbox");
        assert_eq!(json["mode"], "container");
        assert_eq!(roundtrip(&sandbox), sandbox);

        let question = AgentSessionOverrideFieldV1::Question {
            policy: AgentQuestionOverrideV1::Reduce {
                required_decision_timeout_seconds: 45,
            },
        };
        let json = serde_json::to_value(&question).unwrap();
        assert_eq!(json["axis"], "question");
        assert_eq!(json["policy"]["kind"], "reduce");
        assert_eq!(roundtrip(&question), question);

        let verification = AgentSessionOverrideFieldV1::Verification {
            reduction: AgentVerificationReductionV1::Off {
                region_id: "rule-1".to_string(),
            },
        };
        assert_eq!(roundtrip(&verification), verification);
    }

    #[test]
    fn modes_session_setup_effective_settings_snapshot_roundtrips() {
        let snapshot = AgentEffectiveSettingsV1 {
            dto_version: AGENT_EFFECTIVE_SETTINGS_DTO_VERSION,
            session_id: "s".to_string(),
            agent_instance_id: "a".to_string(),
            override_revision: 3,
            terminal: false,
            sandbox: AgentSandboxControlV1 {
                effective: SandboxMode::Sandbox,
                allowed: vec![SandboxMode::Sandbox, SandboxMode::Container],
                locked_reason: None,
                pending: Some(SandboxMode::Container),
            },
            mode: AgentModeControlV1 {
                effective: LlmMode::Normal,
                allowed: vec![LlmMode::Defensive, LlmMode::Normal],
                locked_reason: None,
                pending: None,
            },
            verification: AgentVerificationControlV1 {
                regions: vec![AgentVerificationRegionV1 {
                    region_id: "rule-1".to_string(),
                    label: "rule-1".to_string(),
                    enabled: true,
                    can_disable: true,
                    can_restrict: true,
                    pending: false,
                }],
            },
            question: AgentQuestionControlV1 {
                effective: Some(AgentQuestionEffectiveV1 {
                    auto_answer_enabled: true,
                    required_decision_timeout_seconds: 30,
                    host_ceiling_seconds: 3600,
                    can_disable_auto_answer: true,
                    max_required_decision_timeout_seconds: 3600,
                }),
                locked_reason: None,
                pending: None,
            },
        };
        assert_eq!(roundtrip(&snapshot), snapshot);
    }

    #[test]
    fn modes_session_setup_override_status_labels_are_snake_case() {
        assert_eq!(
            serde_json::to_value(AgentSessionOverrideStatusV1::StaleRevision).unwrap(),
            serde_json::json!("stale_revision")
        );
        assert_eq!(
            serde_json::to_value(AgentSessionOverrideStatusV1::RejectedEscalation).unwrap(),
            serde_json::json!("rejected_escalation")
        );
    }
}
