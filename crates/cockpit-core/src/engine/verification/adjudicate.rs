//! Adjudicator for ArtifactWrite verification.
//!
//! Structured verdict: `{ decision: approve | block | select, selected_candidate?,
//! feedback }`. In Gate mode `select` degrades to `block` with the candidate's
//! critique as feedback.

use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

use crate::agents::{OnAdjudicationFailure, VerificationMode};
use crate::engine::model::Model;
use crate::engine::model::UtilityCallSite;
use crate::engine::tool::ToolDefinition;

use super::generate::{CandidateKind, CollectedCandidate, GeneratorAnswer};

#[derive(Debug, Clone, PartialEq)]
pub struct AdjudicatorVerdict {
    pub decision: AdjudicatorDecision,
    pub selected: Option<Uuid>,
    pub feedback: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdjudicatorDecision {
    Approve,
    Block,
    Select,
}

#[cfg(test)]
thread_local! {
    static ADJUDICATOR_OVERRIDE: std::cell::RefCell<Option<AdjudicatorVerdict>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_adjudicator_override(verdict: AdjudicatorVerdict) {
    ADJUDICATOR_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(verdict));
}

#[cfg(test)]
pub(crate) fn clear_adjudicator_override() {
    ADJUDICATOR_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn take_override() -> Option<AdjudicatorVerdict> {
    ADJUDICATOR_OVERRIDE.with(|slot| slot.borrow_mut().take())
}

#[cfg(not(test))]
fn take_override() -> Option<AdjudicatorVerdict> {
    None
}

pub fn apply_mode(
    verdict: AdjudicatorVerdict,
    mode: VerificationMode,
    candidates: &[CollectedCandidate],
) -> AdjudicatorVerdict {
    if mode == VerificationMode::Gate && verdict.decision == AdjudicatorDecision::Select {
        let feedback = verdict
            .selected
            .and_then(|id| {
                candidates
                    .iter()
                    .find(|candidate| candidate.candidate_id == id)
                    .map(|candidate| candidate.answer.critique.clone())
            })
            .filter(|text| !text.is_empty())
            .unwrap_or(verdict.feedback);
        return AdjudicatorVerdict {
            decision: AdjudicatorDecision::Block,
            selected: None,
            feedback,
        };
    }
    verdict
}

pub async fn adjudicate(
    model: &Model,
    original: &Value,
    candidates: &[CollectedCandidate],
    instructions: &str,
    _on_failure: OnAdjudicationFailure,
) -> Result<AdjudicatorVerdict> {
    if let Some(verdict) = take_override() {
        return Ok(verdict);
    }
    let tool = ToolDefinition {
        name: "verification_verdict".to_string(),
        description: "Adjudicate the original change and its verification candidates.".to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "decision": { "type": "string", "enum": ["approve", "block", "select"] },
                "selected_candidate": { "type": ["string", "null"] },
                "feedback": { "type": "string" }
            },
            "required": ["decision", "selected_candidate", "feedback"],
            "additionalProperties": false
        }),
    };
    let candidate_json = candidates
        .iter()
        .map(|candidate| {
            serde_json::json!({
                "candidate_id": candidate.candidate_id,
                "kind": match candidate.answer.kind {
                    CandidateKind::Revision => "revision",
                    CandidateKind::ApproveOriginal => "approve_original",
                    CandidateKind::Flag => "flag",
                },
                "args": candidate.answer.args,
                "critique": candidate.answer.critique,
            })
        })
        .collect::<Vec<_>>();
    let prompt = serde_json::to_string_pretty(&serde_json::json!({
        "original_args": original,
        "candidates": candidate_json,
        "instructions_excerpt": instructions,
    }))?;
    let calls = model
        .tool_completion_for(
            UtilityCallSite::VerificationAdjudication,
            "Judge a proposed file write or edit against the supplied instructions and candidates. Return exactly one structured verdict through the verification_verdict tool.",
            &prompt,
            &tool,
        )
        .await?;
    let call = calls
        .iter()
        .find(|call| call.function.name == tool.name)
        .ok_or_else(|| anyhow::anyhow!("verification adjudicator returned no verdict tool call"))?;
    parse_verdict(&call.function.arguments)
}

pub fn parse_verdict(value: &Value) -> Result<AdjudicatorVerdict> {
    let decision = match value.get("decision").and_then(Value::as_str) {
        Some("approve") => AdjudicatorDecision::Approve,
        Some("block") => AdjudicatorDecision::Block,
        Some("select") => AdjudicatorDecision::Select,
        _ => anyhow::bail!("adjudicator decision is not approve|block|select"),
    };
    let selected = value
        .get("selected_candidate")
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok());
    Ok(AdjudicatorVerdict {
        decision,
        selected,
        feedback: value
            .get("feedback")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

pub fn selected_revision<'a>(
    verdict: &AdjudicatorVerdict,
    candidates: &'a [CollectedCandidate],
) -> Option<&'a GeneratorAnswer> {
    let id = verdict.selected?;
    candidates
        .iter()
        .find(|candidate| {
            candidate.candidate_id == id && candidate.answer.kind == CandidateKind::Revision
        })
        .map(|candidate| &candidate.answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_mode_degrades_select_to_block() {
        let id = Uuid::nil();
        let candidates = vec![CollectedCandidate {
            candidate_id: id,
            answer: GeneratorAnswer {
                kind: CandidateKind::Revision,
                args: Some(serde_json::json!({"path": "a.rs"})),
                critique: "use a.rs".into(),
            },
        }];
        let degraded = apply_mode(
            AdjudicatorVerdict {
                decision: AdjudicatorDecision::Select,
                selected: Some(id),
                feedback: String::new(),
            },
            VerificationMode::Gate,
            &candidates,
        );
        assert_eq!(degraded.decision, AdjudicatorDecision::Block);
        assert_eq!(degraded.feedback, "use a.rs");
    }
}
