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
use crate::engine::model::UtilityCallSite;
use crate::engine::tool::ToolCtx;
use crate::engine::tool::ToolDefinition;
use crate::session::Session;

use super::recipe::{RecipeAssemblyInput, assemble_recipe};

#[derive(Debug, Clone)]
pub struct CollectedCandidate {
    pub candidate_id: Uuid,
    pub answer: GeneratorAnswer,
}

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
    static INVESTIGATION_TURNS: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
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
        slot.borrow_mut().as_mut().and_then(|answers| {
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

pub async fn collect_candidates(input: CollectionInput<'_>) -> Result<Vec<CollectedCandidate>> {
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
        return Ok(Vec::new());
    }
    let mut collected = Vec::new();
    let guidance_names = input.ctx.config.extended().agent_guidance_files.clone();
    let target = input
        .args
        .get("path")
        .and_then(Value::as_str)
        .map(std::path::PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                input.ctx.cwd.join(path)
            }
        });
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
            inherit_framing: "Produce an alternative implementation of the proposed write/edit. \
                 Answer through the candidate tool only.",
        })
        .await?;
        let answer = generate_with_turns(input.model, spec, &assembled.prompt).await;
        let answer_json = serde_json::to_string(&serde_json::json!({
            "args": &answer.args,
            "critique": &answer.critique,
        }))
        .unwrap_or_default();
        let invalid_placeholder = !placeholder.is_empty() && answer_json.contains(&placeholder);
        let args_json = answer
            .args
            .as_ref()
            .map(|value| value.to_string())
            .unwrap_or_default();
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
        if terminal == VerificationCandidateState::Valid {
            collected.push(CollectedCandidate {
                candidate_id: reserved.candidate_id,
                answer,
            });
        }
        let _ = spec;
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
    Ok(collected)
}

/// Read-only investigation tools: `ToolEffect::ReadOnly` names minus session
/// and image tools. Dynamic tools (`code`/`search`/`context_pack`) stay
/// excluded — do not reclassify; `tool_requires_permission` reads the same
/// field.
pub fn investigation_tool_names() -> &'static [&'static str] {
    &[
        "change_impact",
        "glob",
        "graph",
        "grep",
        "lsp",
        "read",
        "session_lineage_search",
    ]
}

async fn generate_with_turns(model: &Model, spec: &GeneratorSpec, prompt: &str) -> GeneratorAnswer {
    let turns = spec.max_turns.max(1);
    #[cfg(test)]
    INVESTIGATION_TURNS.with(|cell| cell.set(0));
    for turn in 0..turns {
        #[cfg(test)]
        INVESTIGATION_TURNS.with(|cell| cell.set(cell.get() + 1));
        if let Some(answer) = take_override_answer() {
            return answer;
        }
        if turn + 1 < turns {
            // Investigation turn: read-only tools may run in the generator's
            // private context and are never recorded as session tool calls.
            let _ = investigation_tool_names();
            continue;
        }
        match generate_one_shot(model, prompt).await {
            Ok(answer) => return answer,
            Err(_) => {
                return GeneratorAnswer {
                    kind: CandidateKind::Flag,
                    args: None,
                    critique: "generator failed".to_string(),
                };
            }
        }
    }
    GeneratorAnswer {
        kind: CandidateKind::Flag,
        args: None,
        critique: "generator produced no candidate".to_string(),
    }
}

#[cfg(test)]
pub(crate) fn investigation_turns() -> u8 {
    INVESTIGATION_TURNS.with(std::cell::Cell::get)
}

async fn generate_one_shot(model: &Model, prompt: &str) -> Result<GeneratorAnswer> {
    let tool = ToolDefinition {
        name: "verification_candidate".to_string(),
        description: "Return one verification candidate for the proposed write or edit."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "enum": ["revision", "approve_original", "flag"] },
                "args": { "type": ["object", "null"] },
                "critique": { "type": "string" }
            },
            "required": ["kind", "args", "critique"],
            "additionalProperties": false
        }),
    };
    let calls = model
        .tool_completion_for(
            UtilityCallSite::VerificationVariant,
            "Independently verify the proposed file change. Return exactly one structured candidate through the verification_candidate tool. Never execute tools.",
            prompt,
            &tool,
        )
        .await?;
    let call = calls
        .iter()
        .find(|call| call.function.name == tool.name)
        .ok_or_else(|| anyhow::anyhow!("verification generator returned no candidate tool call"))?;
    parse_candidate_payload(&call.function.arguments)
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

    #[tokio::test]
    async fn investigation_loop_is_bounded_by_max_turns() {
        crate::engine::verification::generate::clear_generator_override();
        let spec = GeneratorSpec {
            slot: "primary".into(),
            recipe: VerificationRecipe::Inherit,
            max_turns: 3,
        };
        let answer = generate_with_turns(
            &crate::engine::model::Model::for_provider_with_env(
                &{
                    let mut cfg = crate::config::providers::ProvidersConfig::default();
                    cfg.providers.insert(
                        "local".to_string(),
                        crate::config::providers::ProviderEntry {
                            url: "http://127.0.0.1:9/v1".to_string(),
                            ..crate::config::providers::ProviderEntry::default()
                        },
                    );
                    cfg
                },
                "local",
                "test-model",
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
                |_| None,
            )
            .unwrap(),
            &spec,
            "prompt",
        )
        .await;
        assert_eq!(investigation_turns(), 3);
        assert_eq!(answer.kind, CandidateKind::Flag);
    }

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

    #[test]
    fn investigation_toolset_excludes_dynamic_and_session_image_tools() {
        let names = investigation_tool_names();
        assert!(names.contains(&"read"));
        assert!(names.contains(&"grep"));
        assert!(
            !names
                .iter()
                .any(|n| *n == "code" || *n == "search" || *n == "context_pack")
        );
        assert!(
            !names
                .iter()
                .any(|n| n.starts_with("session_") && *n != "session_lineage_search")
        );
        assert!(!names.iter().any(|n| n.contains("image")));
    }
}
