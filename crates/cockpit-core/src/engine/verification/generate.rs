//! Bounded private candidate generation for ArtifactWrite
//! verification. Candidate bodies are persisted only as
//! [`RedactedVerificationJson`]; they never enter the tool-call audit path.

use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

use crate::agents::{GeneratorSpec, VerificationRecipe};
use crate::db::verification_ledger::{
    CandidateTransitionOutcome, NewVerificationCandidate, RedactedVerificationJson,
    VerificationArtifactKind, VerificationArtifactMember, VerificationArtifactOperation,
    VerificationCandidateState, VerificationDigest,
};
use crate::engine::agent::Agent;
use crate::engine::message::Message;
use crate::engine::model::Model;
use crate::engine::model::UtilityCallSite;
use crate::engine::tool::ToolDefinition;
use crate::engine::tool::{ToolCtx, ToolEffect};
use crate::session::Session;

use super::inference::{VerificationInferenceInput, journaled_verification_inference};
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
    pub profile_snapshot_id: Uuid,
    pub collection_deadline_unix_ms: i64,
    pub original_digest: VerificationDigest,
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
        if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms {
            break;
        }
        let generator_model = if input.profile_snapshot_id.is_nil() {
            #[cfg(test)]
            {
                input.agent.model.clone()
            }
            #[cfg(not(test))]
            {
                anyhow::bail!("verification generator has no immutable profile snapshot")
            }
        } else {
            let Ok(model) = super::models::resolve_profile_utility_model(
                input.session,
                input.ctx,
                input.profile_snapshot_id,
                &spec.slot,
            )
            .await
            else {
                continue;
            };
            model
        };
        let mut generator_model = generator_model.as_ref().clone();
        generator_model
            .set_redact_table_for_config(&input.ctx.config.providers(), input.ctx.redact.clone());
        let (include_linked, last_n) = match &spec.recipe {
            VerificationRecipe::Inherit => (false, 3),
            VerificationRecipe::CleanRoom {
                include_linked_files,
                last_n_reads,
            } => (*include_linked_files, *last_n_reads),
        };
        let Ok(assembled) = assemble_recipe(RecipeAssemblyInput {
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
        .await
        else {
            continue;
        };
        let same_as_author = generator_model.provider_id() == input.model.provider_id()
            && generator_model.model_id_ref() == input.model.model_id_ref();
        let reservation_body = if matches!(spec.recipe, VerificationRecipe::Inherit) {
            let Ok(body) = serde_json::to_string(&serde_json::json!({
                "history": input.history,
                "tools": input.agent.tools.definitions(input.agent.tool_steering),
                "prompt": assembled.prompt,
            })) else {
                continue;
            };
            body
        } else {
            assembled.prompt.clone()
        };
        let reservation_digest = VerificationDigest::of(reservation_body.as_bytes());
        let prices = crate::db::stats::PriceTable::load_default();
        let price = prices.get(generator_model.model_id_ref());
        let reservation =
            super::estimate::estimate_candidate_set(super::estimate::CandidateSetEstimateInput {
                assembled_texts: std::slice::from_ref(&reservation_body),
                encoding: super::estimate::encoding_for_model_id(generator_model.model_id_ref()),
                input_price_per_mtok: price.map(|price| price.input_per_mtok),
                output_price_per_mtok: price.map(|price| price.output_per_mtok),
                max_candidates: 1,
                max_collection_millis: 1,
            });
        let turns = u64::from(spec.max_turns.max(1));
        let reservation_tokens = reservation.tokens.saturating_mul(turns);
        let reserved_cost = reservation.cost_microusd.unwrap_or(0).saturating_mul(turns);
        let now = chrono::Utc::now().timestamp_millis();
        let reserved = match input
            .session
            .db
            .reserve_verification_candidate(
                input.session.id,
                input.operation_id,
                NewVerificationCandidate {
                    artifact_kind: VerificationArtifactKind::ProposedCall,
                    canonical_call_digest: reservation_digest.clone(),
                    artifact_union_digest: reservation_digest.clone(),
                    redacted_summary: RedactedVerificationJson::candidate_summary(
                        reservation_digest.clone(),
                    ),
                    reserved_tokens: i64::try_from(reservation_tokens).unwrap_or(i64::MAX),
                    reserved_cost_microunits: i64::try_from(reserved_cost).unwrap_or(i64::MAX),
                    artifact_members: Vec::new(),
                },
                now,
            )
            .await
        {
            Ok(row) => row,
            Err(_) => continue,
        };
        let Ok(running) = input
            .session
            .db
            .transition_verification_candidate(
                input.session.id,
                input.operation_id,
                reserved.candidate_id,
                reserved.revision,
                VerificationCandidateState::Running,
                reservation_digest.clone(),
                now,
            )
            .await
        else {
            continue;
        };
        if running != CandidateTransitionOutcome::Transitioned {
            continue;
        }
        let answer = if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms {
            GeneratorAnswer {
                kind: CandidateKind::Flag,
                args: None,
                critique: "generator timed out".into(),
            }
        } else {
            generate_with_turns(
                input,
                &generator_model,
                spec,
                &assembled.prompt,
                same_as_author,
            )
            .await
        };
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
        let terminal = if invalid_placeholder {
            VerificationCandidateState::Invalid
        } else if answer.critique == "generator timed out" {
            VerificationCandidateState::TimedOut
        } else if answer.args.is_none() && answer.kind != CandidateKind::ApproveOriginal {
            VerificationCandidateState::Malformed
        } else {
            VerificationCandidateState::Valid
        };
        let descriptor = candidate_descriptor(input, &answer, digest.clone());
        let finalized = input
            .session
            .db
            .finalize_verification_candidate_descriptor(
                input.session.id,
                input.operation_id,
                reserved.candidate_id,
                reserved.revision + 1,
                descriptor,
                now,
            )
            .await;
        let terminal_revision = match finalized {
            Ok(row) => row.revision,
            Err(_) => {
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
                        now,
                    )
                    .await;
                continue;
            }
        };
        let _ = input
            .session
            .db
            .transition_verification_candidate(
                input.session.id,
                input.operation_id,
                reserved.candidate_id,
                terminal_revision,
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
    }
    input
        .session
        .db
        .close_verification_collection(
            input.session.id,
            input.operation_id,
            started.revision,
            chrono::Utc::now().timestamp_millis(),
        )
        .await?;
    Ok(collected)
}

/// Read-only investigation tools: `ToolEffect::ReadOnly` names minus session
/// and image tools. Dynamic tools (`code`/`search`/`context_pack`) stay
/// excluded — do not reclassify; `tool_requires_permission` reads the same
/// field.
fn is_private_investigation_tool(tool: &dyn crate::engine::tool::Tool) -> bool {
    let name = tool.name();
    tool.is_registered_ordinary_operation()
        && tool.effect() == ToolEffect::ReadOnly
        && !name.starts_with("session_")
        && !name.contains("image")
        && !name.contains("audio")
        && !name.contains("video")
        && !name.contains("generation")
}

async fn generate_with_turns(
    input: &CollectionInput<'_>,
    model: &Model,
    spec: &GeneratorSpec,
    prompt: &str,
    same_as_author: bool,
) -> GeneratorAnswer {
    let turns = spec
        .max_turns
        .max(1)
        .min(crate::agents::MAX_GENERATOR_TURNS);
    let mut private_history = if matches!(spec.recipe, VerificationRecipe::Inherit) {
        input.history.to_vec()
    } else {
        Vec::new()
    };
    let candidate_tool = candidate_tool_definition();
    let mut tools = if matches!(spec.recipe, VerificationRecipe::Inherit) && same_as_author {
        input.agent.tools.definitions(input.agent.tool_steering)
    } else if turns > 1 {
        input
            .agent
            .tools
            .definitions(input.agent.tool_steering)
            .into_iter()
            .filter(|definition| {
                input
                    .agent
                    .tools
                    .get(&definition.name)
                    .is_some_and(|tool| is_private_investigation_tool(tool.as_ref()))
            })
            .collect()
    } else {
        Vec::new()
    };
    tools.push(candidate_tool.clone());
    let params = if matches!(spec.recipe, VerificationRecipe::Inherit) && same_as_author {
        input.agent.params.clone()
    } else {
        crate::engine::model::ModelParams::default()
    };
    for turn in investigation_turn_budget(turns) {
        if let Some(answer) = take_override_answer() {
            return answer;
        }
        match generate_one_shot(
            input,
            model,
            prompt,
            &private_history,
            &tools,
            params.clone(),
        )
        .await
        {
            Ok(GeneratorTurn::Answer(answer)) => return answer,
            Ok(GeneratorTurn::Investigate(choice, calls)) if turn + 1 < turns => {
                private_history.push(Message::Assistant {
                    id: None,
                    content: choice,
                });
                for call in calls {
                    let text = match input.agent.tools.get(&call.function.name) {
                        Some(tool) if is_private_investigation_tool(tool.as_ref()) => {
                            let remaining = input
                                .collection_deadline_unix_ms
                                .saturating_sub(chrono::Utc::now().timestamp_millis());
                            if remaining <= 0 {
                                "Error: verification investigation deadline elapsed".to_string()
                            } else {
                                tokio::select! {
                                    _ = input.ctx.cancel.cancelled() => {
                                        "Error: verification investigation cancelled".to_string()
                                    }
                                    result = tokio::time::timeout(
                                        std::time::Duration::from_millis(remaining as u64),
                                        tool.call(call.function.arguments.clone(), input.ctx),
                                    ) => match result {
                                        Ok(Ok(output)) => output.content,
                                        Ok(Err(error)) => format!("Error: {error}"),
                                        Err(_) => "Error: verification investigation deadline elapsed".to_string(),
                                    }
                                }
                            }
                        }
                        Some(_) => {
                            "Error: this tool is disabled in private verification investigation"
                                .to_string()
                        }
                        None => "Error: unknown investigation tool".to_string(),
                    };
                    private_history.push(crate::engine::message::tool_result_message_for(
                        &call,
                        &call.function.name,
                        text,
                    ));
                }
            }
            Ok(GeneratorTurn::Investigate(_, _)) => {
                return GeneratorAnswer {
                    kind: CandidateKind::Flag,
                    args: None,
                    critique: "generator exhausted its investigation turn cap".to_string(),
                };
            }
            Err(_) => {
                return GeneratorAnswer {
                    kind: CandidateKind::Flag,
                    args: None,
                    critique: if chrono::Utc::now().timestamp_millis()
                        >= input.collection_deadline_unix_ms
                    {
                        "generator timed out".to_string()
                    } else {
                        "generator failed".to_string()
                    },
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

fn investigation_turn_budget(max_turns: u8) -> std::ops::Range<u8> {
    0..max_turns.max(1).min(crate::agents::MAX_GENERATOR_TURNS)
}

enum GeneratorTurn {
    Answer(GeneratorAnswer),
    Investigate(
        Vec<rig::message::AssistantContent>,
        Vec<crate::engine::message::ToolCall>,
    ),
}

fn candidate_tool_definition() -> ToolDefinition {
    ToolDefinition {
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
    }
}

async fn generate_one_shot(
    input: &CollectionInput<'_>,
    model: &Model,
    prompt: &str,
    history: &[Message],
    tools: &[ToolDefinition],
    params: crate::engine::model::ModelParams,
) -> Result<GeneratorTurn> {
    let tool = candidate_tool_definition();
    let choice = journaled_verification_inference(VerificationInferenceInput {
        session: input.ctx.session.clone(),
        model,
        config: &input.ctx.config,
        system: "Independently verify the proposed file change. You may use only the advertised read-only investigation tools. Return exactly one structured candidate through verification_candidate; no other tool can produce a final answer.",
        history,
        prompt,
        tools,
        params,
        agent_name: &format!("{}:verification-generator", input.agent.name),
        site: UtilityCallSite::VerificationVariant,
        cancel: &input.ctx.cancel,
        deadline_unix_ms: Some(input.collection_deadline_unix_ms),
    }).await?;
    let calls = crate::engine::message::collect_tool_calls(&choice);
    let call = calls
        .iter()
        .find(|call| call.function.name == tool.name)
        .map(|call| parse_candidate_payload(&call.function.arguments))
        .transpose()?;
    if let Some(answer) = call {
        Ok(GeneratorTurn::Answer(answer))
    } else {
        Ok(GeneratorTurn::Investigate(choice, calls))
    }
}

fn candidate_descriptor(
    input: &CollectionInput<'_>,
    answer: &GeneratorAnswer,
    digest: VerificationDigest,
) -> NewVerificationCandidate {
    if answer.kind == CandidateKind::ApproveOriginal {
        return NewVerificationCandidate {
            artifact_kind: VerificationArtifactKind::ProposedCall,
            canonical_call_digest: input.original_digest.clone(),
            artifact_union_digest: input.original_digest.clone(),
            redacted_summary: RedactedVerificationJson::candidate_summary(
                input.original_digest.clone(),
            ),
            reserved_tokens: 0,
            reserved_cost_microunits: 0,
            artifact_members: Vec::new(),
        };
    }
    let args = answer.args.as_ref().unwrap_or(input.args);
    let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
    let content = args
        .get("content")
        .or_else(|| args.get("new_string"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let target = if std::path::Path::new(path).is_absolute() {
        std::path::PathBuf::from(path)
    } else {
        input.ctx.cwd.join(path)
    };
    let operation_kind = if input.resolved_name.contains("write") && !target.exists() {
        VerificationArtifactOperation::Add
    } else {
        VerificationArtifactOperation::Modify
    };
    NewVerificationCandidate {
        artifact_kind: VerificationArtifactKind::WriteChangeSet,
        canonical_call_digest: digest.clone(),
        artifact_union_digest: digest.clone(),
        redacted_summary: RedactedVerificationJson::candidate_summary(digest),
        reserved_tokens: 0,
        reserved_cost_microunits: 0,
        artifact_members: vec![VerificationArtifactMember {
            operation_kind,
            affected_path_digest: VerificationDigest::of(path.as_bytes()),
            prior_path_digest: None,
            content_digest: Some(VerificationDigest::of(content.as_bytes())),
            binary_metadata_digest: None,
            mode_digest: None,
        }],
    }
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
    fn investigation_loop_budget_is_positive_and_hard_bounded() {
        assert_eq!(investigation_turn_budget(0).count(), 1);
        assert_eq!(investigation_turn_budget(3).count(), 3);
        assert_eq!(
            investigation_turn_budget(u8::MAX).count(),
            usize::from(crate::agents::MAX_GENERATOR_TURNS)
        );
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
        struct Fixture(&'static str, ToolEffect);
        #[async_trait::async_trait]
        impl crate::engine::tool::Tool for Fixture {
            fn name(&self) -> &str {
                self.0
            }
            fn description(&self) -> &str {
                "fixture"
            }
            fn parameters(&self) -> Value {
                serde_json::json!({})
            }
            fn effect(&self) -> ToolEffect {
                self.1
            }
            async fn call(
                &self,
                _args: Value,
                _ctx: &ToolCtx,
            ) -> Result<crate::engine::tool::ToolOutput> {
                Ok(crate::engine::tool::ToolOutput::text(""))
            }
        }
        assert!(is_private_investigation_tool(&Fixture(
            "read",
            ToolEffect::ReadOnly
        )));
        assert!(!is_private_investigation_tool(&Fixture(
            "code",
            ToolEffect::Dynamic
        )));
        assert!(!is_private_investigation_tool(&Fixture(
            "session_read",
            ToolEffect::ReadOnly
        )));
        assert!(!is_private_investigation_tool(&Fixture(
            "read_image",
            ToolEffect::ReadOnly
        )));
    }
}
