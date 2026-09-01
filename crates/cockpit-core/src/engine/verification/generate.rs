//! Bounded private candidate generation for ArtifactWrite
//! verification. Candidate bodies are persisted only as
//! [`RedactedVerificationJson`]; they never enter the tool-call audit path.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use futures::future::join_all;
use serde_json::Value;
use uuid::Uuid;

use crate::agents::{GeneratorSpec, VerificationCandidateDispatch, VerificationRecipe};
use crate::config::providers::CacheMode;
use crate::db::verification_ledger::{
    CandidateTransitionOutcome, NewVerificationCandidate, RedactedVerificationJson,
    VerificationArtifactKind, VerificationCandidateState, VerificationDigest,
};
use crate::engine::agent::Agent;
use crate::engine::message::{Message, ToolDefinition};
use crate::engine::model::Model;
use crate::engine::model::UtilityCallSite;
use crate::engine::tool::{Tool, ToolCtx, ToolEffect};
use crate::session::Session;

use super::inference::{
    VerificationInferenceInput, effective_verification_route, journaled_verification_inference,
};
use super::recipe::{RecipeAssemblyInput, assemble_recipe, generator_recipe_for_slot};

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

/// The semantic generator result and whether any provider request completed
/// are deliberately separate. A completed request can warm a cache even when
/// its returned tool payload is malformed or otherwise unusable as a
/// verification candidate.
struct GenerationExecution {
    outcome: GenerationOutcome,
    completed_provider_request: bool,
}

impl GenerationExecution {
    fn without_provider_request(outcome: GenerationOutcome) -> Self {
        Self {
            outcome,
            completed_provider_request: false,
        }
    }
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
    pub candidate_dispatch: VerificationCandidateDispatch,
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

fn inherit_uses_author_context(spec: &GeneratorSpec, same_as_author: bool) -> bool {
    matches!(spec.recipe, VerificationRecipe::Inherit) && same_as_author
}

fn candidate_is_adjudicable(
    terminal: VerificationCandidateState,
    accepted: &Result<CandidateTransitionOutcome>,
) -> bool {
    terminal == VerificationCandidateState::Valid
        && matches!(accepted, Ok(CandidateTransitionOutcome::Transitioned))
}

/// The complete first-turn request materialization. Dispatch consumes this
/// snapshot rather than reassembling after a warm request, when workspace
/// inputs may have changed.
struct PreparedGeneratorCandidate<'a> {
    index: usize,
    spec: &'a GeneratorSpec,
    model: Model,
    prompt: String,
    initial_history: Vec<Message>,
    tools: Vec<ToolDefinition>,
    params: crate::engine::model::ModelParams,
    reservation_body: String,
    cacheable_request_prefix: String,
}

struct CandidateExecution {
    candidate: Option<CollectedCandidate>,
    /// Stronger than a stream poll: a successful generator run has completed
    /// the request that may populate the provider cache.
    completed_provider_request: bool,
}

impl CandidateExecution {
    fn not_dispatched() -> Self {
        Self {
            candidate: None,
            completed_provider_request: false,
        }
    }
}

async fn prepare_generator_candidate<'spec>(
    input: &CollectionInput<'_>,
    index: usize,
    spec: &'spec GeneratorSpec,
) -> Result<Option<PreparedGeneratorCandidate<'spec>>> {
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
    if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms {
        return Ok(None);
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
            return Ok(None);
        };
        model
    };
    let mut generator_model = generator_model.as_ref().clone();
    generator_model
        .set_redact_table_for_config(&input.ctx.config.providers(), input.ctx.redact.clone());
    // Slot identity, not provider/model equality, decides cache-prefix
    // inheritance. Two distinct slots may intentionally bind the same
    // provider model but have different custody and prompt identities.
    let same_as_author = is_author_slot(&spec.slot, &input.author_slot);
    let recipe = generator_recipe_for_slot(&spec.recipe, same_as_author);
    let (include_linked, last_n) = match recipe.as_ref() {
        VerificationRecipe::Inherit => (false, crate::agents::DEFAULT_CLEAN_ROOM_LAST_N_READS),
        VerificationRecipe::CleanRoom {
            include_linked_files,
            last_n_reads,
            ..
        } => (*include_linked_files, *last_n_reads),
    };
    let assembled = assemble_recipe(RecipeAssemblyInput {
        recipe: recipe.as_ref(),
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
    let tools = generator_tools(input, spec, same_as_author);
    let initial_history = if inherit_uses_author_context(spec, same_as_author) {
        input.history
    } else {
        &[]
    };
    let Ok(reservation_body) =
        generator_budget_text(&generator_model, &assembled.prompt, initial_history, &tools)
    else {
        return Ok(None);
    };
    let params = if inherit_uses_author_context(spec, same_as_author) {
        input.agent.params.clone()
    } else {
        crate::engine::model::ModelParams::default()
    };
    // This is the full first-turn system/history/prompt/tool surface, plus
    // endpoint identity and parameters. Conservative equality is intentional:
    // a false split only loses an optimization; a false match corrupts it.
    let cacheable_request_prefix = serde_json::to_string(&serde_json::json!({
        // A slot is a custody boundary even when two slots happen to resolve
        // to the same configured provider/model today.
        "slot": &spec.slot,
        "provider": generator_model.provider_id(),
        "model": generator_model.model_id_ref(),
        "request": &reservation_body,
        "params": format!("{params:?}"),
    }))?;
    Ok(Some(PreparedGeneratorCandidate {
        index,
        spec,
        model: generator_model,
        prompt: assembled.prompt,
        initial_history: initial_history.to_vec(),
        tools,
        params,
        reservation_body,
        cacheable_request_prefix,
    }))
}

async fn collect_one_candidate(
    input: &CollectionInput<'_>,
    candidate: &PreparedGeneratorCandidate<'_>,
    provider_handoff: Option<&AtomicBool>,
) -> Result<CandidateExecution> {
    let placeholder = input.ctx.redact.placeholder().to_string();
    if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms {
        return Ok(CandidateExecution::not_dispatched());
    }
    let spec = candidate.spec;
    let generator_model = &candidate.model;
    let reservation_digest = VerificationDigest::of(candidate.reservation_body.as_bytes());
    let prices = crate::db::stats::PriceTable::load_default();
    let price = super::estimate::model_prices(&prices, generator_model.model_id_ref());
    let reservation = super::estimate::estimate_multi_turn_candidate(
        &candidate.reservation_body,
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
        Err(_) => return Ok(CandidateExecution::not_dispatched()),
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
        return Ok(CandidateExecution::not_dispatched());
    };
    if running != CandidateTransitionOutcome::Transitioned {
        return Ok(CandidateExecution::not_dispatched());
    }
    let generated = if chrono::Utc::now().timestamp_millis() >= input.collection_deadline_unix_ms {
        GenerationExecution::without_provider_request(GenerationOutcome::TimedOut)
    } else {
        generate_with_turns(
            input,
            generator_model,
            spec,
            candidate,
            reservation_tokens,
            reserved_cost,
            provider_handoff,
        )
        .await
    };
    let completed_provider_request = generated.completed_provider_request;
    let (mut answer, forced_terminal) = materialize_generation(generated.outcome);
    // Candidate arguments cross the same schema-repair/path-normalization
    // boundary as an authored call before they can become adjudicable.
    // Dispatch repeats this check as a TOCTOU defense; canonicalizing here
    // also makes the candidate digest describe the exact selected call.
    let invalid_arguments = if answer.kind == CandidateKind::Revision {
        match answer.args.take() {
            Some(args) => match canonical_candidate_args(input, args) {
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
            return Ok(CandidateExecution {
                candidate: None,
                completed_provider_request,
            });
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
    Ok(CandidateExecution {
        candidate: candidate_is_adjudicable(terminal, &accepted).then_some(CollectedCandidate {
            candidate_id: reserved.candidate_id,
            answer,
        }),
        completed_provider_request,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateDispatchPlan {
    scheduled_mode: VerificationCandidateDispatch,
    warm_candidate: Option<usize>,
}

/// Equivalence is based on each candidate's immutable, realized first-turn
/// request snapshot, not merely its declarative generator spec. A matching
/// spec can otherwise observe changed guidance, linked files, targets, or
/// curated read history while its sibling is warming.
fn shares_cacheable_request_prefix(
    first: &PreparedGeneratorCandidate<'_>,
    second: &PreparedGeneratorCandidate<'_>,
) -> bool {
    shares_realized_cacheable_request_prefix(
        &first.cacheable_request_prefix,
        &second.cacheable_request_prefix,
    )
}

fn shares_realized_cacheable_request_prefix(first: &str, second: &str) -> bool {
    first == second
}

fn candidate_dispatch_plan(
    requested: VerificationCandidateDispatch,
    candidates: &[usize],
    slot_supports_observed_cache_hits: bool,
) -> CandidateDispatchPlan {
    if requested == VerificationCandidateDispatch::WarmThenFanout
        && candidates.len() > 1
        && slot_supports_observed_cache_hits
    {
        CandidateDispatchPlan {
            scheduled_mode: VerificationCandidateDispatch::WarmThenFanout,
            warm_candidate: candidates.first().copied(),
        }
    } else {
        CandidateDispatchPlan {
            scheduled_mode: VerificationCandidateDispatch::Parallel,
            warm_candidate: None,
        }
    }
}

fn slot_supports_observed_cache_hits(
    input: &CollectionInput<'_>,
    candidate: &PreparedGeneratorCandidate<'_>,
) -> bool {
    cache_warm_is_eligible(
        input
            .ctx
            .config
            .providers()
            .resolve_cache(
                candidate.model.provider_id(),
                candidate.model.model_id_ref(),
            )
            .mode,
        input
            .session
            .has_observed_cache_hit_for_endpoint(&candidate.model.cache_endpoint_identity()),
    )
}

fn cache_warm_is_eligible(cache_mode: CacheMode, observed_cache_hit: bool) -> bool {
    cache_mode != CacheMode::None && observed_cache_hit
}

/// A warm candidate is an ordering fence, never an eligibility gate. Every
/// scheduled candidate must retain the same opportunity to run as it has in
/// parallel mode, even when the preceding request cannot populate the cache.
fn fanout_follows_warm(plan: &CandidateDispatchPlan) -> bool {
    plan.warm_candidate.is_some()
}

fn dispatched_cache_read_count(
    warm_completed_provider_request: bool,
    fanout_provider_handoffs: impl IntoIterator<Item = bool>,
) -> usize {
    if warm_completed_provider_request {
        fanout_provider_handoffs
            .into_iter()
            .filter(|reached_provider| *reached_provider)
            .count()
    } else {
        0
    }
}

async fn collect_dispatch_group<T, F>(
    slot: &str,
    candidates: &[T],
    plan: &CandidateDispatchPlan,
    candidate_index: impl Fn(&T) -> usize,
    collect_one: F,
) -> Result<CollectedDispatchGroup>
where
    F: for<'candidate> Fn(
        &'candidate T,
        Option<&'candidate AtomicBool>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CandidateExecution>> + 'candidate>,
    >,
{
    let mut collected = Vec::new();
    let candidate_count = candidates.len();
    if let Some(warm_index) = plan.warm_candidate {
        let warm = candidates
            .iter()
            .find(|candidate| candidate_index(candidate) == warm_index)
            .expect("warm candidate must belong to its dispatch group");
        let (warm_completed_provider_request, mut dispatch_error) =
            match collect_one(warm, None).await {
                Ok(execution) => {
                    if let Some(candidate) = execution.candidate {
                        collected.push((warm_index, candidate));
                    }
                    (execution.completed_provider_request, None)
                }
                Err(error) => (false, Some(error)),
            };
        let fanout = candidates
            .iter()
            .filter(|candidate| candidate_index(candidate) != warm_index)
            .collect::<Vec<_>>();
        // Each sibling gets its own execution observation. Planned fan-out is
        // not telemetry: deadline, model, budget, and ledger gates can refuse
        // a sibling before its first provider request.
        let fanout_handoffs = fanout
            .iter()
            .map(|_| AtomicBool::new(false))
            .collect::<Vec<_>>();
        if fanout_follows_warm(plan) {
            for result in join_all(fanout.iter().zip(fanout_handoffs.iter()).map(
                |(candidate, handoff)| async move {
                    Ok::<_, anyhow::Error>((
                        candidate_index(candidate),
                        collect_one(candidate, Some(handoff)).await?,
                    ))
                },
            ))
            .await
            {
                match result {
                    Ok((index, execution)) => {
                        if let Some(candidate) = execution.candidate {
                            collected.push((index, candidate));
                        }
                    }
                    Err(error) => {
                        if dispatch_error.is_none() {
                            dispatch_error = Some(error);
                        }
                    }
                }
            }
        }
        if let Some(error) = dispatch_error {
            return Err(error);
        }
        let cache_read_candidate_count = dispatched_cache_read_count(
            warm_completed_provider_request,
            fanout_handoffs
                .iter()
                .map(|handoff| handoff.load(Ordering::Acquire)),
        );
        return Ok(CollectedDispatchGroup {
            collected,
            telemetry: serde_json::json!({
                "slot": slot,
                "actual_mode": match plan.scheduled_mode {
                    VerificationCandidateDispatch::Parallel => "parallel",
                    VerificationCandidateDispatch::WarmThenFanout => "warm_then_fanout",
                },
                "candidate_count": candidate_count,
                "warm_completed_provider_request": warm_completed_provider_request,
                "cache_read_candidate_count": cache_read_candidate_count,
            }),
        });
    }
    for result in join_all(candidates.iter().map(|candidate| async move {
        Ok::<_, anyhow::Error>((
            candidate_index(candidate),
            collect_one(candidate, None).await?,
        ))
    }))
    .await
    {
        let (index, execution) = result?;
        if let Some(candidate) = execution.candidate {
            collected.push((index, candidate));
        }
    }
    Ok(CollectedDispatchGroup {
        collected,
        telemetry: serde_json::json!({
            "slot": slot,
            "actual_mode": "parallel",
            "candidate_count": candidate_count,
            "cache_read_candidate_count": 0,
        }),
    })
}

struct CollectedDispatchGroup {
    collected: Vec<(usize, CollectedCandidate)>,
    telemetry: serde_json::Value,
}

/// Collect candidates concurrently by cacheable request prefix. A warm group
/// completes its first request before the remaining matching-prefix requests
/// begin; distinct prefixes make their own warm/fan-out decision and proceed
/// independently.
pub async fn collect_candidates(input: &CollectionInput<'_>) -> Result<Vec<CollectedCandidate>> {
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

    let effective_candidate_count = input
        .generators
        .len()
        .min(usize::from(input.max_candidates))
        .min(usize::from(crate::agents::MAX_VERIFICATION_CANDIDATES));
    let mut prepared = Vec::with_capacity(effective_candidate_count);
    for candidate in join_all(
        input
            .generators
            .iter()
            .take(effective_candidate_count)
            .enumerate()
            .map(|(index, spec)| prepare_generator_candidate(input, index, spec)),
    )
    .await
    {
        if let Some(candidate) = candidate? {
            prepared.push(candidate);
        }
    }

    let mut groups = Vec::<Vec<PreparedGeneratorCandidate<'_>>>::new();
    for candidate in prepared {
        if let Some(group) = groups.iter_mut().find(|group| {
            group
                .first()
                .is_some_and(|first| shares_cacheable_request_prefix(first, &candidate))
        }) {
            group.push(candidate);
        } else {
            groups.push(vec![candidate]);
        }
    }

    let mut scheduled = Vec::with_capacity(groups.len());
    for candidates in groups {
        let supports_cache = match candidates.first() {
            Some(candidate) => slot_supports_observed_cache_hits(input, candidate),
            None => false,
        };
        let indices = candidates
            .iter()
            .map(|candidate| candidate.index)
            .collect::<Vec<_>>();
        let plan = candidate_dispatch_plan(input.candidate_dispatch, &indices, supports_cache);
        let slot = candidates
            .first()
            .expect("dispatch group must contain at least one candidate")
            .spec
            .slot
            .clone();
        scheduled.push((slot, candidates, plan));
    }

    let mut indexed = Vec::new();
    let mut telemetry = Vec::with_capacity(scheduled.len());
    for group in join_all(scheduled.iter().map(|(slot, candidates, plan)| {
        collect_dispatch_group(
            slot,
            candidates,
            plan,
            |candidate| candidate.index,
            |candidate, handoff| Box::pin(collect_one_candidate(input, candidate, handoff)),
        )
    }))
    .await
    {
        let group = group?;
        indexed.extend(group.collected);
        telemetry.push(group.telemetry);
    }
    if let Err(error) = input
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            None,
            None,
            &serde_json::json!({
                "purpose": "verification_candidate_dispatch",
                "requested_mode": match input.candidate_dispatch {
                    VerificationCandidateDispatch::Parallel => "parallel",
                    VerificationCandidateDispatch::WarmThenFanout => "warm_then_fanout",
                },
                "cache_prefix_groups": telemetry,
            }),
        )
        .await
    {
        tracing::warn!(%error, "record verification candidate dispatch telemetry failed");
    }
    indexed.sort_by_key(|(index, _)| *index);

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
    Ok(indexed
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect())
}

/// Read-only investigation tools: `ToolEffect::ReadOnly` names minus session
/// and image tools. Dynamic tools (`code`/`search`/`context_pack`) stay
/// excluded — do not reclassify; `tool_requires_permission` reads the same
/// field.
fn is_private_investigation_tool(tool: &dyn Tool) -> bool {
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
    model: &Model,
    prompt: &str,
    history: &[Message],
    tools: &[ToolDefinition],
) -> Result<String> {
    let (system, tools, _) = effective_verification_route(GENERATOR_SYSTEM, model, tools);
    Ok(serde_json::to_string(&serde_json::json!({
        "system": system,
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
    generator_budget_text(&agent.model, prompt, history, &tools)
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
    candidate: &PreparedGeneratorCandidate<'_>,
    reserved_tokens: u64,
    reserved_cost_microusd: u64,
    provider_handoff: Option<&AtomicBool>,
) -> GenerationExecution {
    let turns = spec
        .max_turns
        .max(1)
        .min(crate::agents::MAX_GENERATOR_TURNS);
    let mut private_history = candidate.initial_history.clone();
    let tools = &candidate.tools;
    let params = &candidate.params;
    let prices = crate::db::stats::PriceTable::load_default();
    let price = super::estimate::model_prices(&prices, model.model_id_ref());
    let encoding = super::estimate::encoding_for_model_id(model.model_id_ref());
    let mut budget = GeneratorTurnBudget {
        remaining_tokens: reserved_tokens,
        remaining_cost_microusd: reserved_cost_microusd,
    };
    let mut completed_provider_request = false;
    for turn in investigation_turn_budget(turns) {
        if let Some(answer) = take_override_answer() {
            return GenerationExecution::without_provider_request(GenerationOutcome::Answer(
                answer,
            ));
        }
        let Ok(turn_body) =
            generator_budget_text(model, &candidate.prompt, &private_history, tools)
        else {
            return GenerationExecution {
                outcome: GenerationOutcome::Failed,
                completed_provider_request,
            };
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
            return GenerationExecution {
                outcome: GenerationOutcome::BudgetExhausted,
                completed_provider_request,
            };
        }
        let generated = generate_one_shot(
            input,
            model,
            &candidate.prompt,
            &private_history,
            tools,
            (*params).clone(),
            provider_handoff,
        )
        .await;
        completed_provider_request |= generated.completed_provider_request;
        match generated.turn {
            Ok(GeneratorTurn::Answer(answer)) => {
                return GenerationExecution {
                    outcome: GenerationOutcome::Answer(answer),
                    completed_provider_request,
                };
            }
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
                            execute_private_investigation_call(
                                tool.as_ref(),
                                call.function.arguments.clone(),
                                input.ctx,
                                remaining,
                            )
                            .await
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
                return GenerationExecution {
                    outcome: GenerationOutcome::Answer(GeneratorAnswer {
                        kind: CandidateKind::Flag,
                        args: None,
                        critique: "generator exhausted its investigation turn cap".to_string(),
                    }),
                    completed_provider_request,
                };
            }
            Err(_) => {
                return GenerationExecution {
                    outcome: if chrono::Utc::now().timestamp_millis()
                        >= input.collection_deadline_unix_ms
                    {
                        GenerationOutcome::TimedOut
                    } else {
                        GenerationOutcome::Failed
                    },
                    completed_provider_request,
                };
            }
        }
    }
    GenerationExecution {
        outcome: GenerationOutcome::Answer(GeneratorAnswer {
            kind: CandidateKind::Flag,
            args: None,
            critique: "generator produced no candidate".to_string(),
        }),
        completed_provider_request,
    }
}

fn investigation_turn_budget(max_turns: u8) -> std::ops::Range<u8> {
    0..max_turns.max(1).min(crate::agents::MAX_GENERATOR_TURNS)
}

/// Execute a curated ReadOnly investigation tool in the generator's private
/// context. The host call is real (generators need current bytes) but must
/// never write the author's lock-read identity — Decision 4's tracker is a
/// freshness gate, and Stage 7 investigation is not a session tool call.
async fn execute_private_investigation_call(
    tool: &dyn Tool,
    args: Value,
    author_ctx: &ToolCtx,
    remaining_ms: i64,
) -> String {
    if remaining_ms <= 0 {
        return "Error: verification investigation deadline elapsed".to_string();
    }
    let ctx = author_ctx.for_private_investigation();
    tokio::select! {
        _ = author_ctx.cancel.cancelled() => {
            "Error: verification investigation cancelled".to_string()
        }
        result = tokio::time::timeout(
            std::time::Duration::from_millis(remaining_ms as u64),
            tool.call(args, &ctx),
        ) => match result {
            Ok(Ok(output)) => output.content.model_text().to_string(),
            Ok(Err(error)) => format!("Error: {error}"),
            Err(_) => "Error: verification investigation deadline elapsed".to_string(),
        }
    }
}

enum GeneratorTurn {
    Answer(GeneratorAnswer),
    Investigate(
        Vec<rig::message::AssistantContent>,
        Vec<crate::engine::message::ToolCall>,
    ),
}

struct GeneratedTurn {
    turn: Result<GeneratorTurn>,
    completed_provider_request: bool,
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
    provider_handoff: Option<&AtomicBool>,
) -> GeneratedTurn {
    let tool = candidate_tool_definition();
    let choice = journaled_verification_inference(VerificationInferenceInput {
        session: input.ctx.session.clone(),
        model,
        config: &input.ctx.config,
        interrupts: input.ctx.interrupts.as_ref(),
        system: GENERATOR_SYSTEM,
        history,
        prompt,
        tools,
        params,
        agent_name: &format!("{}:verification-generator", input.agent.name),
        site: UtilityCallSite::VerificationVariant,
        cancel: &input.ctx.cancel,
        provider_handoff,
        deadline_unix_ms: Some(input.collection_deadline_unix_ms),
    })
    .await;
    generated_turn_from_provider_result(choice, &tool.name)
}

fn generated_turn_from_provider_result(
    provider_result: Result<Vec<rig::message::AssistantContent>>,
    candidate_tool_name: &str,
) -> GeneratedTurn {
    // Successful inference proves the provider completed the request. Parse
    // afterward so malformed candidate data cannot erase the cache-warm fact.
    let completed_provider_request = provider_request_completed(&provider_result);
    let turn = provider_result.and_then(|choice| {
        let calls = crate::engine::message::collect_tool_calls(&choice);
        let call = calls
            .iter()
            .find(|call| call.function.name == candidate_tool_name)
            .map(|call| parse_candidate_payload(&call.function.arguments))
            .transpose()?;
        if let Some(answer) = call {
            Ok(GeneratorTurn::Answer(answer))
        } else {
            Ok(GeneratorTurn::Investigate(choice, calls))
        }
    });
    GeneratedTurn {
        turn,
        completed_provider_request,
    }
}

fn provider_request_completed<T>(provider_result: &Result<T>) -> bool {
    provider_result.is_ok()
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
    fn warm_then_fanout_marks_each_matching_prefix_sibling_as_a_cache_read() {
        let plan = candidate_dispatch_plan(
            VerificationCandidateDispatch::WarmThenFanout,
            &[0, 1, 2],
            true,
        );

        assert_eq!(
            plan.scheduled_mode,
            VerificationCandidateDispatch::WarmThenFanout
        );
        assert_eq!(plan.warm_candidate, Some(0));
    }

    #[test]
    fn warm_then_fanout_falls_back_to_parallel_without_cache_hits_or_siblings() {
        for (candidates, observed_cache_hit) in [(&[0, 1][..], false), (&[0][..], true)] {
            let plan = candidate_dispatch_plan(
                VerificationCandidateDispatch::WarmThenFanout,
                candidates,
                observed_cache_hit,
            );
            assert_eq!(plan.scheduled_mode, VerificationCandidateDispatch::Parallel);
            assert_eq!(plan.warm_candidate, None);
        }
    }

    #[test]
    fn cache_mode_none_never_arms_a_warm_then_fanout() {
        let plan = candidate_dispatch_plan(
            VerificationCandidateDispatch::WarmThenFanout,
            &[0, 1],
            cache_warm_is_eligible(CacheMode::None, true),
        );
        assert_eq!(plan.scheduled_mode, VerificationCandidateDispatch::Parallel);
    }

    #[test]
    fn dispatch_telemetry_distinguishes_ordering_from_confirmed_cache_reads() {
        let plan =
            candidate_dispatch_plan(VerificationCandidateDispatch::WarmThenFanout, &[0, 1], true);
        assert_eq!(
            plan.scheduled_mode,
            VerificationCandidateDispatch::WarmThenFanout
        );
        assert!(
            fanout_follows_warm(&plan),
            "a failed, cancelled, or pre-dispatch warm must not suppress sibling attempts"
        );
        assert_eq!(
            dispatched_cache_read_count(false, [true, false]),
            0,
            "a failed warm must not claim that its later sibling requests were cache reads"
        );
        assert_eq!(
            dispatched_cache_read_count(true, [true, false]),
            1,
            "only fan-out siblings that crossed their own provider handoff are cache-read dispatches"
        );
    }

    #[tokio::test]
    async fn collect_dispatch_group_attempts_siblings_after_unsuccessful_warm_execution() {
        for warm_outcome in ["failed", "cancelled", "timed_out", "pre_dispatch_refused"] {
            let attempted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed_attempts = attempted.clone();
            let plan = candidate_dispatch_plan(
                VerificationCandidateDispatch::WarmThenFanout,
                &[0, 1, 2],
                true,
            );

            let group = collect_dispatch_group(
                "primary",
                &[0, 1, 2],
                &plan,
                |candidate| *candidate,
                move |candidate, provider_handoff| {
                    observed_attempts
                        .lock()
                        .unwrap()
                        .push((*candidate, provider_handoff.is_some()));
                    Box::pin(async {
                        Ok(CandidateExecution {
                            candidate: None,
                            completed_provider_request: false,
                        })
                    })
                },
            )
            .await
            .expect(
                "a refused warm result is a terminal dispatch observation, not a collector error",
            );

            assert_eq!(
                *attempted.lock().unwrap(),
                vec![(0, false), (1, true), (2, true)],
                "{warm_outcome} must preserve every sibling attempt while retaining its fan-out observation"
            );
            assert_eq!(
                group.telemetry["actual_mode"], "warm_then_fanout",
                "{warm_outcome} still runs the requested warm-then-fanout ordering"
            );
            assert_eq!(
                group.telemetry["cache_read_candidate_count"], 0,
                "{warm_outcome} must not claim cache reads without a completed warm request"
            );
        }
    }

    #[tokio::test]
    async fn collect_dispatch_group_attempts_siblings_after_a_warm_collector_error() {
        let attempted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed_attempts = attempted.clone();
        let plan = candidate_dispatch_plan(
            VerificationCandidateDispatch::WarmThenFanout,
            &[0, 1, 2],
            true,
        );

        let result = collect_dispatch_group(
            "primary",
            &[0, 1, 2],
            &plan,
            |candidate| *candidate,
            move |candidate, provider_handoff| {
                observed_attempts
                    .lock()
                    .unwrap()
                    .push((*candidate, provider_handoff.is_some()));
                Box::pin(async move {
                    if *candidate == 0 {
                        anyhow::bail!("warm collector failed")
                    }
                    Ok(CandidateExecution::not_dispatched())
                })
            },
        )
        .await;
        let error = match result {
            Ok(_) => {
                panic!("the original warm collector error must still be reported after fan-out")
            }
            Err(error) => error,
        };

        assert!(error.to_string().contains("warm collector failed"));
        assert_eq!(
            *attempted.lock().unwrap(),
            vec![(0, false), (1, true), (2, true)],
            "a collector error must not suppress later scheduled candidates"
        );
    }

    #[test]
    fn malformed_warm_payload_preserves_completed_provider_request() {
        let provider_result = Ok(vec![rig::message::AssistantContent::ToolCall(
            crate::engine::message::ToolCall {
                id: rig::message::ToolCallId::new_or_mint("malformed-candidate"),
                provider: None,
                function: rig::message::ToolFunction {
                    name: "verification_candidate".to_string(),
                    arguments: serde_json::json!({"kind": "not-a-candidate"}),
                },
                signature: None,
                additional_params: None,
            },
        )]);
        let warm = generated_turn_from_provider_result(provider_result, "verification_candidate");
        assert!(
            warm.turn.is_err(),
            "the semantic payload can fail after a completed provider request"
        );
        assert!(warm.completed_provider_request);

        let plan =
            candidate_dispatch_plan(VerificationCandidateDispatch::WarmThenFanout, &[0, 1], true);
        assert!(
            fanout_follows_warm(&plan),
            "payload parsing must not erase a completed warm request or suppress its fan-out"
        );
    }

    #[test]
    fn parallel_never_serializes_a_cache_warm() {
        let plan = candidate_dispatch_plan(VerificationCandidateDispatch::Parallel, &[0, 1], true);
        assert_eq!(plan.scheduled_mode, VerificationCandidateDispatch::Parallel);
        assert_eq!(plan.warm_candidate, None);
    }

    #[test]
    fn cache_warm_groups_require_identical_realized_request_snapshots() {
        let prefix = r#"{"provider":"p","prompt":"before"}"#;
        let changed_workspace_input = r#"{"provider":"p","prompt":"after"}"#;

        assert!(shares_realized_cacheable_request_prefix(prefix, prefix));
        assert!(
            !shares_realized_cacheable_request_prefix(prefix, changed_workspace_input),
            "matching generator specs cannot share a cache group if their realized workspace inputs differ"
        );
    }

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
    fn inherit_author_context_is_reserved_for_the_author_slot() {
        let spec = GeneratorSpec {
            slot: "author".into(),
            recipe: VerificationRecipe::Inherit,
            max_turns: 1,
        };
        assert!(inherit_uses_author_context(&spec, true));
        assert!(!inherit_uses_author_context(&spec, false));

        let clean_room = GeneratorSpec {
            slot: "reviewer".into(),
            recipe: VerificationRecipe::clean_room_default(),
            max_turns: 1,
        };
        assert!(!inherit_uses_author_context(&clean_room, true));
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
            "read_image",
            ToolEffect::ReadOnly
        )));
    }

    #[tokio::test]
    async fn private_investigation_read_does_not_write_author_lock_read_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let unread = tmp.path().join("unread.rs");
        std::fs::write(&unread, "fn unread() {}\n").unwrap();

        let output = execute_private_investigation_call(
            &crate::tools::read::ReadTool,
            serde_json::json!({"path": "unread.rs"}),
            &ctx,
            5_000,
        )
        .await;
        assert!(
            output.contains("fn unread()"),
            "investigation must still return current bytes: {output}"
        );
        assert!(
            !ctx.locks
                .has_read(&unread, &ctx.lock_identity, ctx.session.id),
            "investigation read must not satisfy the author's §3c freshness gate"
        );
        let persisted = ctx.session.db.list_lock_reads().await.unwrap();
        assert!(
            persisted.is_empty(),
            "investigation must not persist author lock_reads rows: {persisted:?}"
        );

        let err = crate::tools::write::WriteTool
            .call(
                serde_json::json!({"path": "unread.rs", "content": "fn written() {}\n"}),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("read it first"),
            "existing-file write after investigation-only read must still require the author to read: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&unread).unwrap(),
            "fn unread() {}\n"
        );
    }

    #[tokio::test]
    async fn private_investigation_read_does_not_refresh_a_stale_author_read() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let path = tmp.path().join("stale.rs");
        std::fs::write(&path, "fn original() {}\n").unwrap();
        ctx.locks
            .note_read(&path, &ctx.lock_identity, ctx.session.id)
            .await;
        let before = ctx.session.db.list_lock_reads().await.unwrap();
        assert_eq!(
            before.len(),
            1,
            "author note_read must persist a lock_reads row"
        );
        let hash_before = before
            .iter()
            .find(|row| row.path.ends_with("stale.rs"))
            .and_then(|row| row.read_hash);
        assert!(
            hash_before.is_some(),
            "author note_read must capture a content hash"
        );

        std::fs::write(&path, "fn changed() {}\n").unwrap();
        let output = execute_private_investigation_call(
            &crate::tools::read::ReadTool,
            serde_json::json!({"path": "stale.rs"}),
            &ctx,
            5_000,
        )
        .await;
        assert!(
            output.contains("fn changed()"),
            "investigation must observe current bytes: {output}"
        );

        let after = ctx.session.db.list_lock_reads().await.unwrap();
        assert_eq!(
            before.len(),
            after.len(),
            "investigation must not insert a new lock_reads identity"
        );
        let hash_after = after
            .iter()
            .find(|row| row.path.ends_with("stale.rs"))
            .and_then(|row| row.read_hash);
        assert_eq!(
            hash_before, hash_after,
            "investigation must not refresh the author's recorded hash"
        );

        let err = crate::tools::write::WriteTool
            .call(
                serde_json::json!({"path": "stale.rs", "content": "fn proposed() {}\n"}),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("changed on disk since you read it"),
            "a stale author proposal must not look fresh after an investigation read: {err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fn changed() {}\n");
    }
}
