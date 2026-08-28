//! Bounded private candidate generation for ArtifactWrite
//! verification. Candidate bodies are persisted only as
//! [`RedactedVerificationJson`]; they never enter the tool-call audit path.

use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

use crate::agents::{GeneratorSpec, VerificationRecipe};
use crate::db::verification_ledger::{
    CandidateTransitionOutcome, NewVerificationCandidate, RedactedVerificationJson,
    VerificationArtifactKind, VerificationCandidateState, VerificationDigest,
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

const GENERATOR_SYSTEM: &str = "Independently verify the proposed file change. You may use only \
    the advertised read-only investigation tools. Return exactly one structured candidate through \
    verification_candidate; no other tool can produce a final answer.";

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

enum GenerationOutcome {
    Answer(GeneratorAnswer),
    TimedOut,
    BudgetExhausted,
    Failed,
}

#[derive(Debug, Clone, Copy)]
struct GeneratorTurnBudget {
    remaining_tokens: u64,
    remaining_cost_microusd: u64,
}

impl GeneratorTurnBudget {
    fn debit(&mut self, estimate: super::estimate::PreCollectionEstimate) -> bool {
        let Some(cost) = estimate.cost_microusd else {
            return false;
        };
        if estimate.tokens > self.remaining_tokens || cost > self.remaining_cost_microusd {
            return false;
        }
        self.remaining_tokens -= estimate.tokens;
        self.remaining_cost_microusd -= cost;
        true
    }
}

fn materialize_generation(
    generated: GenerationOutcome,
) -> (GeneratorAnswer, Option<VerificationCandidateState>) {
    match generated {
        GenerationOutcome::Answer(answer) => (answer, None),
        GenerationOutcome::TimedOut => (
            GeneratorAnswer {
                kind: CandidateKind::Flag,
                args: None,
                critique: "generator timed out".into(),
            },
            Some(VerificationCandidateState::TimedOut),
        ),
        GenerationOutcome::BudgetExhausted => (
            GeneratorAnswer {
                kind: CandidateKind::Flag,
                args: None,
                critique: "generator budget exhausted".into(),
            },
            Some(VerificationCandidateState::Cancelled),
        ),
        GenerationOutcome::Failed => (
            GeneratorAnswer {
                kind: CandidateKind::Flag,
                args: None,
                critique: "generator failed".into(),
            },
            Some(VerificationCandidateState::Malformed),
        ),
    }
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
    pub ctx: &'a ToolCtx,
    pub history: &'a [Message],
    pub resolved_name: &'a str,
    pub args: &'a Value,
    pub generators: &'a [GeneratorSpec],
    pub max_candidates: u16,
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub workspace_root: &'a std::path::Path,
    pub profile_snapshot_id: Uuid,
    pub collection_deadline_unix_ms: i64,
    pub original_digest: VerificationDigest,
    /// Authoring model slot of the agent that emitted the write/edit.
    /// Inherit cache identity is same-slot as this name (Decision 3).
    pub author_slot: String,
}

fn is_author_slot(slot: &str, author_slot: &str) -> bool {
    slot == author_slot
}

fn candidate_is_adjudicable(
    terminal: VerificationCandidateState,
    accepted: &Result<CandidateTransitionOutcome>,
) -> bool {
    terminal == VerificationCandidateState::Valid
        && matches!(accepted, Ok(CandidateTransitionOutcome::Transitioned))
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
    let effective_candidate_count = input
        .generators
        .len()
        .min(usize::from(input.max_candidates))
        .min(usize::from(crate::agents::MAX_VERIFICATION_CANDIDATES));
    for spec in input.generators.iter().take(effective_candidate_count) {
        if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms {
            break;
        }
        let generator_model = if input.profile_snapshot_id.is_nil() {
            // Compiled definition grant path: no profile snapshot is bound
            // (local CLI/TUI dispatch). Run the generator on the author's
            // live model, matching intercept's grant-path estimate.
            input.agent.model.clone()
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
        // Slot identity, not provider/model equality, decides cache-prefix
        // inheritance. Two distinct slots may intentionally bind the same
        // provider model but have different custody and prompt identities.
        let same_as_author = is_author_slot(&spec.slot, &input.author_slot);
        let tools = generator_tools(&input, spec, same_as_author);
        let initial_history = if matches!(spec.recipe, VerificationRecipe::Inherit) {
            input.history
        } else {
            &[]
        };
        let Ok(reservation_body) =
            generator_budget_text(&assembled.prompt, initial_history, &tools)
        else {
            continue;
        };
        let reservation_digest = VerificationDigest::of(reservation_body.as_bytes());
        let prices = crate::db::stats::PriceTable::load_default();
        let price = super::estimate::model_prices(&prices, generator_model.model_id_ref());
        let reservation = super::estimate::estimate_multi_turn_candidate(
            &reservation_body,
            super::estimate::encoding_for_model_id(generator_model.model_id_ref()),
            price.map(|price| price.0),
            price.map(|price| price.1),
            spec.max_turns,
        );
        let reservation_tokens = reservation.tokens;
        let reserved_cost = reservation.cost_microusd.unwrap_or(0);
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
        let generated =
            if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms {
                GenerationOutcome::TimedOut
            } else {
                generate_with_turns(
                    input,
                    &generator_model,
                    spec,
                    &assembled.prompt,
                    same_as_author,
                    reservation_tokens,
                    reserved_cost,
                )
                .await
            };
        let (mut answer, forced_terminal) = materialize_generation(generated);
        // Candidate arguments cross the same schema-repair/path-normalization
        // boundary as an authored call before they can become adjudicable.
        // Dispatch repeats this check as a TOCTOU defense; canonicalizing here
        // also makes the candidate digest describe the exact selected call.
        let invalid_arguments = if answer.kind == CandidateKind::Revision {
            match answer.args.take() {
                Some(args) => match canonical_candidate_args(&input, args) {
                    Ok(args) => {
                        answer.args = Some(args);
                        false
                    }
                    Err(_) => true,
                },
                None => true,
            }
        } else {
            false
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
        let terminal = if let Some(terminal) = forced_terminal {
            terminal
        } else if invalid_placeholder || invalid_arguments {
            VerificationCandidateState::Invalid
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
        let accepted = input
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
        if candidate_is_adjudicable(terminal, &accepted) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdvertisedGeneratorToolMode {
    AuthorSchemas,
    Investigation,
    None,
}

fn advertised_generator_tool_mode(
    spec: &GeneratorSpec,
    same_as_author: bool,
) -> AdvertisedGeneratorToolMode {
    let turns = spec
        .max_turns
        .max(1)
        .min(crate::agents::MAX_GENERATOR_TURNS);
    if turns > 1 {
        AdvertisedGeneratorToolMode::Investigation
    } else if matches!(spec.recipe, VerificationRecipe::Inherit) && same_as_author {
        AdvertisedGeneratorToolMode::AuthorSchemas
    } else {
        AdvertisedGeneratorToolMode::None
    }
}

fn generator_tools(
    input: &CollectionInput<'_>,
    spec: &GeneratorSpec,
    same_as_author: bool,
) -> Vec<ToolDefinition> {
    // Stage 7's investigation loop advertises the curated read-only set
    // even on inherit/author-slot. Decision 3's full author schemas apply
    // only to Stage 4's single-shot cache prefix (`maxTurns == 1`).
    let mut tools = match advertised_generator_tool_mode(spec, same_as_author) {
        AdvertisedGeneratorToolMode::Investigation => input
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
            .collect(),
        AdvertisedGeneratorToolMode::AuthorSchemas => {
            input.agent.tools.definitions(input.agent.tool_steering)
        }
        AdvertisedGeneratorToolMode::None => Vec::new(),
    };
    // Keep the author's definitions byte-for-byte and in their original order;
    // the private terminal tool is additive.
    tools.push(candidate_tool_definition());
    tools
}

fn generator_budget_text(
    prompt: &str,
    history: &[Message],
    tools: &[ToolDefinition],
) -> Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "system": GENERATOR_SYSTEM,
        "history": history,
        "prompt": prompt,
        "tools": tools,
    }))?)
}

/// Pre-collection callers do not yet have the runtime's curated tool subset.
/// Charging the complete author tool definitions is a safe superset and keeps
/// the operation estimate conservative for every recipe/slot combination.
pub(super) fn conservative_generator_budget_text(
    agent: &Agent,
    prompt: &str,
    history: &[Message],
) -> Result<String> {
    let mut tools = agent.tools.definitions(agent.tool_steering);
    tools.push(candidate_tool_definition());
    generator_budget_text(prompt, history, &tools)
}

fn take_bounded_private_output(output: String, remaining: &mut usize) -> String {
    if output.len() <= *remaining {
        *remaining -= output.len();
        return output;
    }
    let mut end = (*remaining).min(output.len());
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    *remaining = 0;
    output[..end].to_string()
}

async fn generate_with_turns(
    input: &CollectionInput<'_>,
    model: &Model,
    spec: &GeneratorSpec,
    prompt: &str,
    same_as_author: bool,
    reserved_tokens: u64,
    reserved_cost_microusd: u64,
) -> GenerationOutcome {
    let turns = spec
        .max_turns
        .max(1)
        .min(crate::agents::MAX_GENERATOR_TURNS);
    let mut private_history = if matches!(spec.recipe, VerificationRecipe::Inherit) {
        input.history.to_vec()
    } else {
        Vec::new()
    };
    let tools = generator_tools(input, spec, same_as_author);
    let params = if matches!(spec.recipe, VerificationRecipe::Inherit) && same_as_author {
        input.agent.params.clone()
    } else {
        crate::engine::model::ModelParams::default()
    };
    let prices = crate::db::stats::PriceTable::load_default();
    let price = super::estimate::model_prices(&prices, model.model_id_ref());
    let encoding = super::estimate::encoding_for_model_id(model.model_id_ref());
    let mut budget = GeneratorTurnBudget {
        remaining_tokens: reserved_tokens,
        remaining_cost_microusd: reserved_cost_microusd,
    };
    for turn in investigation_turn_budget(turns) {
        if let Some(answer) = take_override_answer() {
            return GenerationOutcome::Answer(answer);
        }
        let Ok(turn_body) = generator_budget_text(prompt, &private_history, &tools) else {
            return GenerationOutcome::Failed;
        };
        let turn_estimate =
            super::estimate::estimate_candidate_set(super::estimate::CandidateSetEstimateInput {
                assembled_texts: std::slice::from_ref(&turn_body),
                encoding,
                input_price_per_mtok: price.map(|price| price.0),
                output_price_per_mtok: price.map(|price| price.1),
                max_candidates: 1,
                max_collection_millis: 1,
            });
        if !budget.debit(turn_estimate) {
            return GenerationOutcome::BudgetExhausted;
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
            Ok(GeneratorTurn::Answer(answer)) => return GenerationOutcome::Answer(answer),
            Ok(GeneratorTurn::Investigate(choice, calls)) if turn + 1 < turns => {
                private_history.push(Message::Assistant {
                    id: None,
                    content: choice,
                });
                let mut remaining_read_output = super::estimate::PRIVATE_READ_OUTPUT_BYTES_PER_TURN;
                for call in calls {
                    let raw_text = match input.agent.tools.get(&call.function.name) {
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
                    let text = take_bounded_private_output(raw_text, &mut remaining_read_output);
                    private_history.push(crate::engine::message::tool_result_message_for(
                        &call,
                        &call.function.name,
                        text,
                    ));
                }
            }
            Ok(GeneratorTurn::Investigate(_, _)) => {
                return GenerationOutcome::Answer(GeneratorAnswer {
                    kind: CandidateKind::Flag,
                    args: None,
                    critique: "generator exhausted its investigation turn cap".to_string(),
                });
            }
            Err(_) => {
                return if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms
                {
                    GenerationOutcome::TimedOut
                } else {
                    GenerationOutcome::Failed
                };
            }
        }
    }
    GenerationOutcome::Answer(GeneratorAnswer {
        kind: CandidateKind::Flag,
        args: None,
        critique: "generator produced no candidate".to_string(),
    })
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
        system: GENERATOR_SYSTEM,
        history,
        prompt,
        tools,
        params,
        agent_name: &format!("{}:verification-generator", input.agent.name),
        site: UtilityCallSite::VerificationVariant,
        cancel: &input.ctx.cancel,
        deadline_unix_ms: Some(input.collection_deadline_unix_ms),
    })
    .await?;
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
    // A generator supplied a full substituted tool call, not a host-composed
    // union of write artifacts. Preserve that distinction in the ledger so a
    // verbatim selection is `selected_call`, never `synthesized_write`.
    NewVerificationCandidate {
        artifact_kind: VerificationArtifactKind::ProposedCall,
        canonical_call_digest: digest.clone(),
        artifact_union_digest: digest.clone(),
        redacted_summary: RedactedVerificationJson::candidate_summary(digest),
        reserved_tokens: 0,
        reserved_cost_microunits: 0,
        artifact_members: Vec::new(),
    }
}

fn canonical_candidate_args(input: &CollectionInput<'_>, args: Value) -> Result<Value> {
    let schema = input
        .agent
        .tools
        .get(input.resolved_name)
        .map(|tool| tool.parameters())
        .unwrap_or(Value::Null);
    let mut canonical = crate::engine::model::wire_schema::strip_wire_nulls(&schema, args);
    let repaired = crate::engine::repair::repair(&mut canonical, &schema, input.resolved_name);
    if !repaired.valid {
        anyhow::bail!(
            "verification candidate arguments failed schema validation: {}",
            repaired.error.unwrap_or_else(|| "invalid arguments".into())
        );
    }
    let normalized =
        crate::engine::repair::normalize_paths(&mut canonical, &schema, input.ctx.cwd.as_path());
    if let Some(error) = normalized.error {
        anyhow::bail!("verification candidate path normalization failed: {error}");
    }
    Ok(canonical)
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
    fn multi_turn_generator_budget_exhaustion_terminalizes_mid_loop() {
        let per_turn = super::super::estimate::PreCollectionEstimate {
            tokens: 10,
            cost_microusd: Some(4),
            candidates: 1,
            collection_millis: 1,
        };
        let mut budget = GeneratorTurnBudget {
            remaining_tokens: 15,
            remaining_cost_microusd: 8,
        };
        assert!(budget.debit(per_turn), "the first turn is admitted");
        assert!(
            !budget.debit(per_turn),
            "the growing second turn is refused before provider handoff"
        );
        let (answer, terminal) = materialize_generation(GenerationOutcome::BudgetExhausted);
        assert_eq!(answer.critique, "generator budget exhausted");
        assert_eq!(terminal, Some(VerificationCandidateState::Cancelled));
    }

    #[test]
    fn private_read_output_is_utf8_safe_and_bounded_across_a_turn() {
        let mut remaining = 7;
        let first = take_bounded_private_output("éééé".to_string(), &mut remaining);
        let second = take_bounded_private_output("tail".to_string(), &mut remaining);
        assert!(first.is_char_boundary(first.len()));
        assert!(first.len() + second.len() <= 7);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn inherit_cache_identity_is_the_author_slot_not_a_model_alias() {
        assert!(is_author_slot("author", "author"));
        assert!(is_author_slot("primary", "primary"));
        assert!(!is_author_slot("reviewer", "author"));
        assert!(!is_author_slot("primary", "author"));
        assert!(!is_author_slot("same-model-different-slot", "author"));
    }

    #[test]
    fn multi_turn_inherit_advertises_investigation_tools_not_author_mutating_set() {
        let spec = GeneratorSpec {
            slot: "author".into(),
            recipe: VerificationRecipe::Inherit,
            max_turns: 3,
        };
        assert_eq!(
            advertised_generator_tool_mode(&spec, true),
            AdvertisedGeneratorToolMode::Investigation
        );
        let single = GeneratorSpec {
            slot: "author".into(),
            recipe: VerificationRecipe::Inherit,
            max_turns: 1,
        };
        assert_eq!(
            advertised_generator_tool_mode(&single, true),
            AdvertisedGeneratorToolMode::AuthorSchemas
        );
        assert_eq!(
            advertised_generator_tool_mode(&single, false),
            AdvertisedGeneratorToolMode::None
        );
    }

    #[test]
    fn structured_candidate_tool_preserves_the_exact_author_tool_prefix() {
        let author_tools = vec![
            ToolDefinition {
                name: "read".into(),
                description: "read".into(),
                parameters: serde_json::json!({"type": "object"}),
            },
            ToolDefinition {
                name: "write".into(),
                description: "write".into(),
                parameters: serde_json::json!({"type": "object"}),
            },
        ];
        let mut verification_tools = author_tools.clone();
        verification_tools.push(candidate_tool_definition());
        for (actual, expected) in verification_tools.iter().zip(&author_tools) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.description, expected.description);
            assert_eq!(actual.parameters, expected.parameters);
        }
        assert_eq!(
            verification_tools.last().map(|tool| tool.name.as_str()),
            Some("verification_candidate")
        );
    }

    #[test]
    fn only_db_accepted_terminal_valid_candidates_enter_adjudication() {
        for discarded in [
            CandidateTransitionOutcome::LateResult,
            CandidateTransitionOutcome::AlreadyTerminal,
            CandidateTransitionOutcome::RevisionConflict,
        ] {
            assert!(!candidate_is_adjudicable(
                VerificationCandidateState::Valid,
                &Ok(discarded)
            ));
        }
        assert!(!candidate_is_adjudicable(
            VerificationCandidateState::Invalid,
            &Ok(CandidateTransitionOutcome::Transitioned)
        ));
        assert!(candidate_is_adjudicable(
            VerificationCandidateState::Valid,
            &Ok(CandidateTransitionOutcome::Transitioned)
        ));
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
