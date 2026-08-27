//! Single-shot (and later multi-turn) candidate generation for ArtifactWrite
//! verification. Candidate bodies are persisted only as
//! [`RedactedVerificationJson`]; they never enter the tool-call audit path.

use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

use crate::agents::{GeneratorSpec, VerificationRecipe};
use crate::db::verification_ledger::{
    NewVerificationCandidate, RedactedVerificationJson, VerificationArtifactKind,
    VerificationCandidateState, VerificationDigest,
};
use crate::engine::agent::Agent;
use crate::engine::message::Message;
use crate::engine::model::Model;
use crate::engine::tool::ToolCtx;
use crate::session::Session;

use super::recipe::{RecipeAssemblyInput, assemble_recipe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Revision,
    ApproveOriginal,
    Flag,
}

#[derive(Debug, Clone)]
pub struct GeneratorAnswer {
    pub kind: CandidateKind,
    pub args: Option<Value>,
    pub critique: String,
}

#[cfg(test)]
thread_local! {
    static GENERATOR_OVERRIDE: std::cell::RefCell<Option<Vec<GeneratorAnswer>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_generator_override(answers: Vec<GeneratorAnswer>) {
    GENERATOR_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(answers));
}

#[cfg(test)]
pub(crate) fn clear_generator_override() {
    GENERATOR_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn take_override_answer() -> Option<GeneratorAnswer> {
    GENERATOR_OVERRIDE.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .and_then(|answers| {
                if answers.is_empty() {
                    None
                } else {
                    Some(answers.remove(0))
                }
            })
    })
}

#[cfg(not(test))]
fn take_override_answer() -> Option<GeneratorAnswer> {
    None
}

pub struct CollectionInput<'a> {
    pub session: &'a Session,
    pub agent: &'a Agent,
    pub model: &'a Model,
    pub ctx: &'a ToolCtx,
    pub history: &'a [Message],
    pub resolved_name: &'a str,
    pub args: &'a Value,
    pub generators: &'a [GeneratorSpec],
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub workspace_root: &'a std::path::Path,
}

pub async fn collect_candidates(input: CollectionInput<'_>) -> Result<()> {
    let now = chrono::Utc::now().timestamp_millis();
    let started = input
        .session
        .db
        .start_verification_collection(
            input.session.id,
            input.operation_id,
            input.expected_revision,
            now,
        )
        .await?;
    if started.budget_action.is_some() {
        return Ok(());
    }
    let guidance_names = input
        .ctx
        .config
        .extended()
        .agent_guidance_files
        .clone();
    let target = input
        .args
        .get("path")
        .and_then(Value::as_str)
        .map(std::path::PathBuf::from);
    let target_ref = target.as_deref();
    let placeholder = input.ctx.redact.placeholder().to_string();
    for spec in input.generators {
        let (include_linked, last_n) = match &spec.recipe {
            VerificationRecipe::Inherit => (false, 3),
            VerificationRecipe::CleanRoom {
                include_linked_files,
                last_n_reads,
            } => (*include_linked_files, *last_n_reads),
        };
        let assembled = assemble_recipe(RecipeAssemblyInput {
            recipe: &spec.recipe,
            history: input.history,
            session: input.session,
            workspace_root: input.workspace_root,
            cwd: &input.ctx.cwd,
            target_path: target_ref,
            tool_name: input.resolved_name,
            original_args: input.args,
            guidance_file_names: &guidance_names,
            last_n_reads: last_n,
            include_linked_files: include_linked,
            inherit_framing:
                "Produce an alternative implementation of the proposed write/edit. \
                 Answer through the candidate tool only.",
        })
        .await?;
        let answer = match take_override_answer() {
            Some(answer) => answer,
            None => match generate_one_shot(input.model, &assembled.prompt).await {
                Ok(answer) => answer,
                Err(_) => GeneratorAnswer {
                    kind: CandidateKind::Flag,
                    args: None,
                    critique: "generator failed".to_string(),
                },
            },
        };
        let args_json = answer
            .args
            .as_ref()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let invalid_placeholder = !placeholder.is_empty() && args_json.contains(&placeholder);
        let digest = VerificationDigest::of(args_json.as_bytes());
        let now = chrono::Utc::now().timestamp_millis();
        let reserved = match input
            .session
            .db
            .reserve_verification_candidate(
                input.session.id,
                input.operation_id,
                NewVerificationCandidate {
                    artifact_kind: VerificationArtifactKind::ProposedCall,
                    canonical_call_digest: digest.clone(),
                    artifact_union_digest: digest.clone(),
                    redacted_summary: RedactedVerificationJson::candidate_summary(digest.clone()),
                    reserved_tokens: 1,
                    reserved_cost_microunits: 1,
                    artifact_members: Vec::new(),
                },
                now,
            )
            .await
        {
            Ok(row) => row,
            Err(_) => continue,
        };
        let _ = input
            .session
            .db
            .transition_verification_candidate(
                input.session.id,
                input.operation_id,
                reserved.candidate_id,
                reserved.revision,
                VerificationCandidateState::Running,
                digest.clone(),
                now + 1,
            )
            .await;
        let terminal = if invalid_placeholder {
            VerificationCandidateState::Invalid
        } else if answer.args.is_none() && answer.kind != CandidateKind::ApproveOriginal {
            VerificationCandidateState::Malformed
        } else {
            VerificationCandidateState::Valid
        };
        let _ = input
            .session
            .db
            .transition_verification_candidate(
                input.session.id,
                input.operation_id,
                reserved.candidate_id,
                reserved.revision + 1,
                terminal,
                digest,
                now + 2,
            )
            .await;
        let _ = (spec, answer);
    }
    let _ = input
        .session
        .db
        .close_verification_collection(
            input.session.id,
            input.operation_id,
            started.revision,
            chrono::Utc::now().timestamp_millis(),
        )
        .await;
    Ok(())
}

async fn generate_one_shot(model: &Model, prompt: &str) -> Result<GeneratorAnswer> {
    let _ = (model, prompt);
    // Production generators resolve utility models via the profile-snapshot
    // binding in a follow-up wiring pass. Fail open to a flag so the original
    // still dispatches when no test override and no bound utility model.
    // TODO(verification): dispatch UtilityCallSite::VerificationVariant through
    // WorkerAgentTreeResolverRegistry.utility_models.
    anyhow::bail!("verification generator utility model is not bound")
}

pub fn parse_candidate_payload(value: &Value) -> Result<GeneratorAnswer> {
    let kind = match value.get("kind").and_then(Value::as_str) {
        Some("revision") => CandidateKind::Revision,
        Some("approve_original") => CandidateKind::ApproveOriginal,
        Some("flag") => CandidateKind::Flag,
        _ => anyhow::bail!("candidate kind is not revision|approve_original|flag"),
    };
    Ok(GeneratorAnswer {
        kind,
        args: value.get("args").cloned().filter(|v| !v.is_null()),
        critique: value
            .get("critique")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_candidate_payload_accepts_structured_kinds() {
        let parsed = parse_candidate_payload(&serde_json::json!({
            "kind": "revision",
            "args": {"path": "a.rs", "content": "x"},
            "critique": "prefer x"
        }))
        .unwrap();
        assert_eq!(parsed.kind, CandidateKind::Revision);
        assert_eq!(parsed.args.unwrap()["path"], "a.rs");
    }
}
