//! Dispatch-time verification intercept.
//!
//! Runs after arg repair, path normalization, and every human/host approval
//! gate (safety, loop, cage, /btw, pre-tool hooks) and before
//! `dispatch_one_timed`. Model-vs-model verification never sees a call an
//! approval would have killed.
//!
//! Runtime decisions combine the running agent's compiled definition grant
//! with the immutable session profile region and its exact utility bindings.

use anyhow::{Context, Result};
use serde_json::Value;
use uuid::Uuid;

use crate::agents::{
    GeneratorSpec, OnAdjudicationFailure, OnBudgetExceeded, SelectorPredicate, ToolClass,
    VerificationAction, VerificationBudget, VerificationEstimate, VerificationMode,
    VerificationRecipe, VerificationRule, VerificationSelector, VerificationSubject,
};
use crate::db::stats::PriceTable;
use crate::db::verification_ledger::{
    NewVerificationEnvelope, NewVerificationOperation, VerificationBudgetAction,
    VerificationDigest, VerificationSurrogateKind, VerificationSynthesisTerminal,
};
use crate::engine::agent::Agent;
use crate::engine::model::Model;
use crate::engine::tool::ToolCtx;
use crate::session::Session;

use super::adjudicate::{AdjudicatorDecision, adjudicate, apply_mode, selected_revision};
use super::budget::budget_to_ledger;
use super::classify_tool;
use super::estimate::{
    CandidateSetEstimateInput, encoding_for_model_id, estimate_candidate_set, input_cost_microusd,
};
use super::generate::{CollectionInput, collect_candidates};
use super::recipe::{RecipeAssemblyInput, assemble_recipe, select_guidance_for_target};

/// Outcome of the verification intercept.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VerificationOutcome {
    /// No matching verify rule, no compiled policy, or no durable agent
    /// instance. Dispatch the original call and write no ledger row.
    Skip,
    /// Matching verify rule recorded as dispatch-original. Execute the
    /// original call unchanged.
    DispatchOriginal { plan: VerificationDispatchPlan },
    /// Gate mode blocked the call. Do not execute.
    Block { message: String, operation_id: Uuid },
    /// Revise mode: dispatch substituted args.
    Revise {
        args: Value,
        disclosure: String,
        plan: VerificationDispatchPlan,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerificationDispatchPlan {
    pub operation_id: Uuid,
    pub attempt_revision: i64,
}

pub(crate) struct InterceptInput<'a> {
    pub session: &'a Session,
    pub agent: &'a Agent,
    pub model: &'a Model,
    pub ctx: &'a ToolCtx,
    pub history: &'a [crate::engine::message::Message],
    pub resolved_name: &'a str,
    pub args: &'a Value,
    pub call_id: &'a str,
}

fn snapshot_budget(
    region: &crate::db::agent_installations::RedactedVerificationRegion,
) -> Result<VerificationBudget> {
    Ok(VerificationBudget {
        max_candidates: u16::try_from(
            region
                .count_ceiling
                .context("verification snapshot lacks candidate ceiling")?,
        )
        .context("verification snapshot candidate ceiling exceeds u16")?,
        max_total_tokens: region
            .token_ceiling
            .context("verification snapshot lacks token ceiling")?,
        max_estimated_cost_microusd: region
            .cost_ceiling_micros
            .context("verification snapshot lacks cost ceiling")?,
        max_collection_millis: region
            .max_collection_duration_ms
            .context("verification snapshot lacks collection duration")?,
    })
}

fn rule_from_snapshot(
    region: &crate::db::agent_installations::RedactedVerificationRegion,
) -> Result<VerificationRule> {
    let plan = region
        .execution_plan
        .as_ref()
        .context("enabled verification snapshot lacks its execution plan")?;
    let mode = match plan.mode.as_str() {
        "gate" => VerificationMode::Gate,
        "revise" => VerificationMode::Revise,
        _ => anyhow::bail!("verification snapshot has an invalid mode"),
    };
    let on_budget_exceeded = match plan.on_budget_exceeded.as_str() {
        "refuse" => OnBudgetExceeded::Refuse,
        "dispatch_original" => OnBudgetExceeded::DispatchOriginal,
        _ => anyhow::bail!("verification snapshot has an invalid budget failure policy"),
    };
    let on_adjudication_failure = match plan.on_adjudication_failure.as_str() {
        "refuse" => OnAdjudicationFailure::Refuse,
        "dispatch_original" => OnAdjudicationFailure::DispatchOriginal,
        _ => anyhow::bail!("verification snapshot has an invalid adjudication failure policy"),
    };
    let generators = plan
        .generators
        .iter()
        .map(|generator| GeneratorSpec {
            slot: generator.slot.clone(),
            recipe: match &generator.recipe {
                crate::db::agent_installations::RedactedVerificationRecipe::Inherit => {
                    VerificationRecipe::Inherit
                }
                crate::db::agent_installations::RedactedVerificationRecipe::CleanRoom {
                    include_linked_files,
                    last_n_reads,
                } => VerificationRecipe::CleanRoom {
                    include_linked_files: *include_linked_files,
                    last_n_reads: *last_n_reads,
                },
            },
            max_turns: generator.max_turns,
        })
        .collect();
    let budget = snapshot_budget(region)?;
    Ok(VerificationRule {
        selector: VerificationSelector {
            all_of: vec![SelectorPredicate::ToolClass {
                tool_class: ToolClass::ArtifactWrite,
            }],
            any_of: Vec::new(),
        },
        action: VerificationAction::Verify,
        max_candidates: Some(budget.max_candidates),
        max_total_tokens: Some(budget.max_total_tokens),
        max_estimated_cost_microusd: Some(budget.max_estimated_cost_microusd),
        max_collection_millis: Some(budget.max_collection_millis),
        adjudicator_slot: region.adjudicator_slot.clone(),
        on_budget_exceeded: Some(on_budget_exceeded),
        mode: Some(mode),
        generators,
        profile: None,
        on_adjudication_failure: Some(on_adjudication_failure),
    })
}

/// Resolve the dispatching agent's compiled verification policy and, in
/// record a durable operation and resolve it through collection,
/// adjudication, and actual dispatch for matching ArtifactWrite calls.
pub(crate) async fn intercept_ordinary_call(input: InterceptInput<'_>) -> VerificationOutcome {
    if let Some(payload) = crate::engine::interrupt::current_interrupt_park_payload()
        && payload.tool == input.resolved_name
        && payload.call_id == input.call_id
        && let Some(memo) = payload.verification
    {
        return match memo.outcome {
            crate::db::needs_attention::InterruptVerificationOutcome::DispatchOriginal => {
                VerificationOutcome::DispatchOriginal {
                    plan: VerificationDispatchPlan {
                        operation_id: memo.operation_id,
                        attempt_revision: memo.dispatch_attempt_revision,
                    },
                }
            }
            crate::db::needs_attention::InterruptVerificationOutcome::Block { message } => {
                VerificationOutcome::Block {
                    message,
                    operation_id: memo.operation_id,
                }
            }
            crate::db::needs_attention::InterruptVerificationOutcome::Revise {
                args,
                disclosure,
            } => VerificationOutcome::Revise {
                args,
                disclosure,
                plan: VerificationDispatchPlan {
                    operation_id: memo.operation_id,
                    attempt_revision: memo.dispatch_attempt_revision,
                },
            },
        };
    }
    let Some(tool_class) = classify_tool(input.resolved_name) else {
        return VerificationOutcome::Skip;
    };
    // A durable AgentTree instance is not itself verification policy. Legacy
    // and no-profile agents have instance IDs too, so resolve the immutable
    // grant first and preserve the ordinary byte-identical dispatch path when
    // policy is absent, off, or does not match this write class.
    let Some(instance_id) = input.ctx.agent_instance_id else {
        return VerificationOutcome::Skip;
    };

    match run_verification(input, tool_class, instance_id).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(
                error = %error,
                tool = input.resolved_name,
                "verification intercept failed closed before host dispatch"
            );
            VerificationOutcome::Block {
                message: "verification could not establish its durable decision boundary; revise and re-emit"
                    .to_string(),
                operation_id: Uuid::nil(),
            }
        }
    }
}

async fn run_verification(
    input: InterceptInput<'_>,
    tool_class: ToolClass,
    agent_instance_id: Uuid,
) -> Result<VerificationOutcome> {
    let subject = VerificationSubject {
        tool_class,
        tool_id: input.resolved_name,
        namespace: "host",
    };
    let instance = input
        .session
        .db
        .agent_instance(input.session.id, agent_instance_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("verification agent instance is absent"))?;
    let (profile_snapshot_id, rule, profile_budget) =
        if let Some(profile_snapshot_id) = instance.resolved_profile_snapshot_id {
            let snapshot = input
                .session
                .db
                .agent_profile_snapshot_by_id(input.session.id, profile_snapshot_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("verification profile snapshot is absent"))?
                .reconstruct()?;
            let redacted_subject = crate::db::agent_installations::RedactedVerificationSubject {
                tool_class: Some("artifact_write".into()),
                tool_id: Some(subject.tool_id.into()),
                namespace: Some(subject.namespace.into()),
            };
            let Some(region) = snapshot
                .verification_regions
                .into_iter()
                .find(|region| region.matches(&redacted_subject))
            else {
                return Ok(VerificationOutcome::Skip);
            };
            if !region.enabled {
                return Ok(VerificationOutcome::Skip);
            }
            let budget = snapshot_budget(&region)?;
            (profile_snapshot_id, rule_from_snapshot(&region)?, budget)
        } else {
            #[cfg(test)]
            {
                let Some(grant) = input.agent.vnext_grant.as_ref() else {
                    return Ok(VerificationOutcome::Skip);
                };
                let Some(rule) = grant
                    .verification
                    .as_ref()
                    .and_then(|policy| policy.select(&subject))
                    .cloned()
                else {
                    return Ok(VerificationOutcome::Skip);
                };
                if rule.action == VerificationAction::Off {
                    return Ok(VerificationOutcome::Skip);
                }
                let budget = rule.requested_budget(grant.host_policy.verification_ceiling)?;
                (Uuid::nil(), rule, budget)
            }
            #[cfg(not(test))]
            {
                // A profile-less/legacy agent has no immutable verification
                // authority. Treat the absent snapshot as absent policy so
                // the ordinary write/edit path remains exactly unchanged.
                return Ok(VerificationOutcome::Skip);
            }
        };
    let requested = profile_budget;
    let assembled = serde_json::to_string(&serde_json::json!({
        "tool": input.resolved_name,
        "args": input.args,
    }))?;
    let prices = PriceTable::load_default();
    let mut estimated_tokens = 0_u64;
    let mut estimated_cost = Some(0_u64);
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
    let instructions = select_guidance_for_target(
        input.session,
        input.session.project_root.as_path(),
        input.ctx.cwd.as_path(),
        target.as_deref(),
        &guidance_names,
    )
    .await
    .map(|(_, body)| body)
    .unwrap_or_default();
    for generator in &rule.generators {
        let model = if profile_snapshot_id.is_nil() {
            Some(input.agent.model.clone())
        } else {
            super::models::resolve_profile_utility_model(
                input.session,
                input.ctx,
                profile_snapshot_id,
                &generator.slot,
            )
            .await
            .ok()
        };
        let Some(model) = model else {
            estimated_cost = None;
            continue;
        };
        let (include_linked_files, last_n_reads) = match generator.recipe {
            crate::agents::VerificationRecipe::Inherit => (false, 3),
            crate::agents::VerificationRecipe::CleanRoom {
                include_linked_files,
                last_n_reads,
            } => (include_linked_files, last_n_reads),
        };
        let recipe = assemble_recipe(RecipeAssemblyInput {
            recipe: &generator.recipe,
            history: input.history,
            session: input.session,
            workspace_root: input.session.project_root.as_path(),
            cwd: input.ctx.cwd.as_path(),
            target_path: target.as_deref(),
            tool_name: input.resolved_name,
            original_args: input.args,
            guidance_file_names: &guidance_names,
            last_n_reads,
            include_linked_files,
            inherit_framing: "Produce an alternative implementation of the proposed write/edit. Answer through verification_candidate.",
        }).await?;
        let generator_history =
            if matches!(generator.recipe, crate::agents::VerificationRecipe::Inherit) {
                input.history
            } else {
                &[]
            };
        let assembled_generator = super::generate::conservative_generator_budget_text(
            input.agent,
            &recipe.prompt,
            generator_history,
        )?;
        let price = super::estimate::model_prices(&prices, model.model_id_ref());
        let estimate = super::estimate::estimate_multi_turn_candidate(
            &assembled_generator,
            encoding_for_model_id(model.model_id_ref()),
            price.map(|price| price.0),
            price.map(|price| price.1),
            generator.max_turns,
        );
        estimated_tokens = estimated_tokens.saturating_add(estimate.tokens);
        estimated_cost = match (estimated_cost, estimate.cost_microusd) {
            (Some(total), Some(cost)) => Some(total.saturating_add(cost)),
            _ => None,
        };
    }
    let adjudicator_model = if profile_snapshot_id.is_nil() {
        Some(input.agent.model.clone())
    } else if let Some(slot) = rule.adjudicator_slot.as_deref() {
        super::models::resolve_profile_utility_model(
            input.session,
            input.ctx,
            profile_snapshot_id,
            slot,
        )
        .await
        .ok()
    } else {
        None
    };
    if let Some(model) = &adjudicator_model {
        let price = super::estimate::model_prices(&prices, model.model_id_ref());
        // The live adjudicator request contains the selected instructions and
        // every admitted candidate's full structured answer. Candidate output
        // is bounded by the utility completion cap, so reserve that cap once
        // per generator in addition to the concrete prompt prefix.
        let adjudicator_prefix = serde_json::to_string(&serde_json::json!({
            "original_args": input.args,
            "instructions_excerpt": instructions,
            "candidates": [],
        }))?;
        let estimate = estimate_candidate_set(CandidateSetEstimateInput {
            assembled_texts: std::slice::from_ref(&adjudicator_prefix),
            encoding: encoding_for_model_id(model.model_id_ref()),
            input_price_per_mtok: price.map(|price| price.0),
            output_price_per_mtok: price.map(|price| price.1),
            max_candidates: 1,
            max_collection_millis: requested.max_collection_millis,
        });
        let candidate_input_tokens = (rule.generators.len() as u64)
            .saturating_mul(crate::engine::model::UTILITY_MAX_TOKENS_CAP);
        estimated_tokens = estimated_tokens
            .saturating_add(estimate.tokens)
            .saturating_add(candidate_input_tokens);
        let candidate_input_cost =
            price.map(|price| input_cost_microusd(candidate_input_tokens, price.0));
        estimated_cost = match (estimated_cost, estimate.cost_microusd, candidate_input_cost) {
            (Some(total), Some(cost), Some(candidate_cost)) => {
                Some(total.saturating_add(cost).saturating_add(candidate_cost))
            }
            _ => None,
        };
    } else {
        estimated_cost = None;
    }
    let estimate = match estimated_cost {
        Some(cost) => VerificationEstimate::Known(crate::agents::VerificationBudget {
            max_candidates: u16::try_from(rule.generators.len()).unwrap_or(u16::MAX),
            max_total_tokens: estimated_tokens,
            max_estimated_cost_microusd: cost,
            max_collection_millis: requested.max_collection_millis,
        }),
        None => VerificationEstimate::UnknownPrice,
    };
    let estimate_known = matches!(estimate, VerificationEstimate::Known(_));
    let generators = rule.generators.clone();
    let estimate_exceeds = match estimate {
        VerificationEstimate::Known(estimated) => !profile_budget.contains(estimated),
        VerificationEstimate::UnknownTokens | VerificationEstimate::UnknownPrice => true,
    };
    let recorded_action = if estimate_exceeds {
        Some(
            match rule
                .on_budget_exceeded
                .unwrap_or(OnBudgetExceeded::DispatchOriginal)
            {
                OnBudgetExceeded::Refuse => VerificationBudgetAction::Refuse,
                OnBudgetExceeded::DispatchOriginal => VerificationBudgetAction::DispatchOriginal,
            },
        )
    } else {
        None
    };
    let now = chrono::Utc::now().timestamp_millis();
    let ledger = budget_to_ledger(profile_budget);
    let generator_count = i64::try_from(generators.len()).unwrap_or(0);
    let effective_candidate_count = if recorded_action.is_some() {
        0
    } else {
        generator_count.min(ledger.candidate_count).max(0)
    };
    let original_digest = VerificationDigest::of(assembled.as_bytes());
    let pretool_digest = VerificationDigest::of(
        format!(
            "verification-pretool:{}:{}",
            input.session.id, input.resolved_name
        )
        .as_bytes(),
    );
    let created = input
        .session
        .db
        .create_verification_operation(
            NewVerificationOperation {
                session_id: input.session.id,
                agent_instance_id,
                requested_candidate_count: ledger.candidate_count.max(effective_candidate_count),
                effective_candidate_count,
                total_token_ceiling: ledger.total_token_ceiling,
                estimated_cost_ceiling_microunits: ledger.estimated_cost_ceiling_microunits,
                collection_deadline_unix_ms: now.saturating_add(ledger.collection_duration_ms),
                collection_duration_ms: ledger.collection_duration_ms,
                conservative_token_reservation: if recorded_action.is_some() {
                    0
                } else {
                    i64::try_from(estimated_tokens).unwrap_or(i64::MAX)
                },
                conservative_cost_reservation_microunits: if recorded_action.is_some() {
                    0
                } else {
                    i64::try_from(estimated_cost.unwrap_or_default()).unwrap_or(i64::MAX)
                },
                original_operation_digest: original_digest.clone(),
                pretool_context_capability_digest: pretool_digest,
                estimate_unavailable_action: recorded_action,
                estimate_known,
            },
            now,
        )
        .await?;
    if recorded_action == Some(VerificationBudgetAction::Refuse) {
        return Ok(VerificationOutcome::Block {
            message: "verification budget was exceeded; the configured policy refuses this edit"
                .to_string(),
            operation_id: created.operation_id,
        });
    }
    let deadline = now.saturating_add(ledger.collection_duration_ms);
    if recorded_action == Some(VerificationBudgetAction::DispatchOriginal) {
        let dispatching = input
            .session
            .db
            .start_verification_collection(
                input.session.id,
                created.operation_id,
                created.revision,
                now,
            )
            .await?;
        let plan = reserve_dispatch(
            &input,
            dispatching.operation_id,
            dispatching.revision,
            original_digest,
            VerificationSurrogateKind::NormalizedOriginal,
            input.args,
        )
        .await?;
        return Ok(VerificationOutcome::DispatchOriginal { plan });
    }
    let mut collection_error = None;
    let collected = if !generators.is_empty() {
        match collect_candidates(CollectionInput {
            session: input.session,
            agent: input.agent,
            ctx: input.ctx,
            history: input.history,
            resolved_name: input.resolved_name,
            args: input.args,
            generators: &generators,
            operation_id: created.operation_id,
            expected_revision: created.revision,
            workspace_root: input.session.project_root.as_path(),
            profile_snapshot_id,
            collection_deadline_unix_ms: deadline,
            original_digest: original_digest.clone(),
        })
        .await
        {
            Ok(collected) => collected,
            Err(error) => {
                tracing::warn!(%error, operation_id = %created.operation_id, "verification candidate collection failed");
                collection_error = Some(error);
                let operation = input
                    .session
                    .db
                    .host_verification_operation(input.session.id, created.operation_id)
                    .await?
                    .context("verification operation disappeared after collection failure")?;
                input
                    .session
                    .db
                    .close_verification_collection(
                        input.session.id,
                        created.operation_id,
                        operation.revision,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await?;
                Vec::new()
            }
        }
    } else {
        let started = input
            .session
            .db
            .start_verification_collection(
                input.session.id,
                created.operation_id,
                created.revision,
                now,
            )
            .await?;
        input
            .session
            .db
            .close_verification_collection(
                input.session.id,
                created.operation_id,
                started.revision,
                chrono::Utc::now().timestamp_millis(),
            )
            .await?;
        Vec::new()
    };
    if recorded_action.is_none() {
        let adjudicator = match adjudicator_model {
            Some(model) => Ok(model),
            None if !profile_snapshot_id.is_nil() => {
                super::models::resolve_profile_utility_model(
                    input.session,
                    input.ctx,
                    profile_snapshot_id,
                    rule.adjudicator_slot
                        .as_deref()
                        .context("verification rule has no adjudicator slot")?,
                )
                .await
            }
            None => Err(anyhow::anyhow!(
                "configured verification adjudicator slot is not live"
            )),
        };
        let adjudication_deadline = chrono::Utc::now()
            .timestamp_millis()
            .saturating_add(ledger.collection_duration_ms);
        let adjudication = match collection_error {
            Some(error) => Err(error.context("verification candidate collection failed")),
            None => match adjudicator {
                Ok(adjudicator) => {
                    let mut adjudicator = adjudicator.as_ref().clone();
                    adjudicator.set_redact_table_for_config(
                        &input.ctx.config.providers(),
                        input.ctx.redact.clone(),
                    );
                    adjudicate(
                        input.ctx.session.clone(),
                        &adjudicator,
                        &input.ctx.config,
                        &input.ctx.cancel,
                        &format!("{}:verification-adjudicator", input.agent.name),
                        input.args,
                        &collected,
                        &instructions,
                        adjudication_deadline,
                    )
                    .await
                }
                Err(error) => Err(error),
            },
        };
        let verdict = match adjudication {
            Ok(verdict) => verdict,
            Err(_)
                if rule.resolved_on_adjudication_failure()
                    == crate::agents::OnAdjudicationFailure::DispatchOriginal =>
            {
                super::adjudicate::AdjudicatorVerdict {
                    decision: AdjudicatorDecision::Approve,
                    selected: None,
                    feedback: "adjudicator failed; dispatching original".into(),
                }
            }
            Err(_) => {
                let op = input
                    .session
                    .db
                    .host_verification_operation(input.session.id, created.operation_id)
                    .await?
                    .context("verification operation disappeared")?;
                input
                    .session
                    .db
                    .suppress_verification_synthesis(
                        input.session.id,
                        created.operation_id,
                        op.revision,
                        VerificationSynthesisTerminal::Failed,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await?;
                return Ok(VerificationOutcome::Block {
                    message: "verification adjudication failed; the configured policy refuses this edit; revise and re-emit".into(),
                    operation_id: created.operation_id,
                });
            }
        };
        let verdict = apply_mode(verdict, rule.resolved_mode(), &collected);
        match (rule.resolved_mode(), verdict.decision) {
            (_, AdjudicatorDecision::Approve) => {
                let op = input
                    .session
                    .db
                    .host_verification_operation(input.session.id, created.operation_id)
                    .await?
                    .context("verification operation disappeared")?;
                let dispatching = input
                    .session
                    .db
                    .select_verification_original(
                        input.session.id,
                        created.operation_id,
                        op.revision,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await?;
                let plan = reserve_dispatch(
                    &input,
                    created.operation_id,
                    dispatching.revision,
                    original_digest.clone(),
                    VerificationSurrogateKind::NormalizedOriginal,
                    input.args,
                )
                .await?;
                return Ok(VerificationOutcome::DispatchOriginal { plan });
            }
            (crate::agents::VerificationMode::Gate, AdjudicatorDecision::Block) => {
                let feedback = if verdict.feedback.is_empty() {
                    "verification rejected this change".to_string()
                } else {
                    verdict.feedback
                };
                let op = input
                    .session
                    .db
                    .host_verification_operation(input.session.id, created.operation_id)
                    .await?
                    .context("verification operation disappeared")?;
                input
                    .session
                    .db
                    .suppress_verification_synthesis(
                        input.session.id,
                        created.operation_id,
                        op.revision,
                        VerificationSynthesisTerminal::Refused,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await?;
                return Ok(VerificationOutcome::Block {
                    message: format!(
                        "verification blocked this edit: {feedback}; revise and re-emit"
                    ),
                    operation_id: created.operation_id,
                });
            }
            (crate::agents::VerificationMode::Revise, AdjudicatorDecision::Block) => {
                let feedback = if verdict.feedback.is_empty() {
                    "verification rejected this change".to_string()
                } else {
                    verdict.feedback
                };
                let op = input
                    .session
                    .db
                    .host_verification_operation(input.session.id, created.operation_id)
                    .await?
                    .context("verification operation disappeared")?;
                input
                    .session
                    .db
                    .suppress_verification_synthesis(
                        input.session.id,
                        created.operation_id,
                        op.revision,
                        VerificationSynthesisTerminal::Refused,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await?;
                return Ok(VerificationOutcome::Block {
                    message: format!(
                        "verification blocked this edit: {feedback}; revise and re-emit"
                    ),
                    operation_id: created.operation_id,
                });
            }
            (crate::agents::VerificationMode::Revise, AdjudicatorDecision::Select) => {
                if let Some(answer) = selected_revision(&verdict, &collected)
                    && let Some(applied) = answer.args.clone()
                {
                    let selected_id = verdict
                        .selected
                        .context("selected verdict has no candidate")?;
                    let op = input
                        .session
                        .db
                        .host_verification_operation(input.session.id, created.operation_id)
                        .await?
                        .context("verification operation disappeared")?;
                    let selected = input
                        .session
                        .db
                        .select_verification_candidate(
                            input.session.id,
                            created.operation_id,
                            op.revision,
                            selected_id,
                            chrono::Utc::now().timestamp_millis(),
                        )
                        .await?;
                    let plan = reserve_dispatch(
                        &input,
                        created.operation_id,
                        selected.revision,
                        VerificationDigest::of(applied.to_string().as_bytes()),
                        VerificationSurrogateKind::SelectedCall,
                        &applied,
                    )
                    .await?;
                    let original_call = serde_json::to_string_pretty(input.args)?;
                    let applied_call = serde_json::to_string_pretty(&applied)?;
                    let disclosure = format!(
                        "[cockpit] verification revised this change before applying:\n{}",
                        crate::engine::guidance_diff::unified_diff(&original_call, &applied_call)
                    );
                    return Ok(VerificationOutcome::Revise {
                        args: applied,
                        disclosure,
                        plan,
                    });
                }
                if rule.resolved_on_adjudication_failure()
                    == crate::agents::OnAdjudicationFailure::DispatchOriginal
                {
                    let op = input
                        .session
                        .db
                        .host_verification_operation(input.session.id, created.operation_id)
                        .await?
                        .context("verification operation disappeared")?;
                    let dispatching = input
                        .session
                        .db
                        .select_verification_original(
                            input.session.id,
                            created.operation_id,
                            op.revision,
                            chrono::Utc::now().timestamp_millis(),
                        )
                        .await?;
                    let plan = reserve_dispatch(
                        &input,
                        created.operation_id,
                        dispatching.revision,
                        original_digest.clone(),
                        VerificationSurrogateKind::NormalizedOriginal,
                        input.args,
                    )
                    .await?;
                    return Ok(VerificationOutcome::DispatchOriginal { plan });
                }
                let feedback = if verdict.feedback.is_empty() {
                    "verification rejected this change".to_string()
                } else {
                    verdict.feedback
                };
                let op = input
                    .session
                    .db
                    .host_verification_operation(input.session.id, created.operation_id)
                    .await?
                    .context("verification operation disappeared")?;
                input
                    .session
                    .db
                    .suppress_verification_synthesis(
                        input.session.id,
                        created.operation_id,
                        op.revision,
                        VerificationSynthesisTerminal::NoValidCandidate,
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await?;
                return Ok(VerificationOutcome::Block {
                    message: format!(
                        "verification blocked this edit: {feedback}; revise and re-emit"
                    ),
                    operation_id: created.operation_id,
                });
            }
            _ => {}
        }
    }
    unreachable!("every verification adjudication branch returns")
}

async fn reserve_dispatch(
    input: &InterceptInput<'_>,
    operation_id: Uuid,
    operation_revision: i64,
    batch_digest: VerificationDigest,
    surrogate_kind: VerificationSurrogateKind,
    args: &Value,
) -> Result<VerificationDispatchPlan> {
    let attempt = input
        .session
        .db
        .reserve_verification_dispatch(
            input.session.id,
            operation_id,
            operation_revision,
            &format!("verification-{operation_id}"),
            NewVerificationEnvelope {
                batch_digest,
                surrogate_kind,
                model_visible_projection: serde_json::json!({
                    "operation": input.resolved_name,
                    "arguments": redact_json(args.clone(), input.ctx.redact.as_ref()),
                }),
            },
            chrono::Utc::now().timestamp_millis(),
        )
        .await?;
    Ok(VerificationDispatchPlan {
        operation_id,
        attempt_revision: attempt.revision,
    })
}

fn redact_json(value: Value, table: &crate::redact::RedactionTable) -> Value {
    match value {
        Value::String(value) => Value::String(table.scrub(&value)),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| redact_json(value, table))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, redact_json(value, table)))
                .collect(),
        ),
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{
        EffectiveVnextGrant, ExecutionKind, ModelCapability, ModelLocality, ModelSlot,
        OnBudgetExceeded, SelectorPredicate, ToolClass, VerificationAction, VerificationPolicy,
        VerificationRule, VerificationSelector, VnextAgentDef, VnextHostPolicy,
    };
    use crate::db::agent_tree_decisions::NewAgentInstance;
    use crate::db::tool_calls::Recovery;
    use crate::db::verification_ledger::{VerificationBudgetAction, VerificationEstimateState};
    use crate::engine::agent::tool_dispatch::{DispatchEnv, execute_ordinary_call};
    use crate::engine::agent::{Agent, TurnEvent};
    use crate::engine::message::{Message, ToolCall};
    use crate::engine::model::{Model, ModelParams};
    use crate::engine::tool::{ToolBox, ToolCtx, ToolOutput};
    use crate::redact::RedactionTable;
    use crate::session::Session;
    use async_trait::async_trait;
    use rig::message::{AssistantContent, ToolFunction};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::mpsc;

    struct NamedFixtureTool {
        name: String,
        called: Arc<AtomicBool>,
    }

    struct RevisionFailureTool {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::engine::tool::Tool for RevisionFailureTool {
        fn name(&self) -> &str {
            "write"
        }

        fn description(&self) -> &str {
            "Reject the selected revision while accepting the original fixture."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            })
        }

        async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if args.get("content").and_then(Value::as_str) == Some("revision") {
                anyhow::bail!("selected revision failed host validation")
            }
            Ok(ToolOutput::text("original applied"))
        }
    }

    #[async_trait]
    impl crate::engine::tool::Tool for NamedFixtureTool {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Verification intercept fixture."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" },
                    "old_string": { "type": "string" },
                    "new_string": { "type": "string" }
                }
            })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            self.called.store(true, Ordering::SeqCst);
            Ok(ToolOutput::text("applied"))
        }
    }

    fn test_model() -> Arc<Model> {
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            crate::config::providers::ProviderEntry {
                url: "http://127.0.0.1:9/v1".to_string(),
                ..crate::config::providers::ProviderEntry::default()
            },
        );
        Arc::new(
            Model::for_provider_with_env(
                &cfg,
                "local",
                "test-model",
                Arc::new(RedactionTable::empty()),
                |_| None,
            )
            .expect("test model builds without network"),
        )
    }

    fn test_agent(tools: ToolBox, grant: Option<EffectiveVnextGrant>) -> Agent {
        Agent {
            name: "Build".to_string(),
            system: "system".to_string(),
            role_prompt: "system".to_string(),
            tools,
            model: test_model(),
            params: ModelParams::default(),
            scan_tool_results: false,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: None,
            lock_identity: "Build".to_string(),
            write_scope: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: grant,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            assistant_identity_prefix: None,
        }
    }

    fn tool_call(name: &str, args: Value) -> ToolCall {
        ToolCall {
            id: rig::message::ToolCallId::new_or_mint("call-1".to_string()),
            provider: rig::message::ProviderCallId::new("provider-call-1".to_string()),
            function: ToolFunction {
                name: name.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        }
    }

    fn push_assistant_call(history: &mut Vec<Message>, call: &ToolCall) {
        history.push(Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(call.clone())],
        });
    }

    fn last_tool_result_text(history: &[Message]) -> String {
        use rig::message::{ToolResultContent, UserContent};
        let Some(Message::User { content }) = history.last() else {
            panic!("expected trailing tool result, got {history:?}");
        };
        content
            .iter()
            .find_map(|part| match part {
                UserContent::ToolResult(result) => result.content.iter().find_map(|result_part| {
                    if let ToolResultContent::Text(text) = result_part {
                        Some(text.text.clone())
                    } else {
                        None
                    }
                }),
                _ => None,
            })
            .expect("tool result text")
    }

    fn host() -> VnextHostPolicy {
        VnextHostPolicy::for_session_config(&crate::config::extended::ExtendedConfig::default())
    }

    fn slot() -> ModelSlot {
        ModelSlot {
            purpose: "primary".to_string(),
            min_context_tokens: 1,
            required_capabilities: vec![ModelCapability::TextGeneration],
            locality: ModelLocality::Any,
            allow_default_fallback: false,
            suggested_models: vec![],
        }
    }

    fn verify_grant(action: VerificationAction) -> EffectiveVnextGrant {
        let (adjudicator, budgets, on_budget) = match action {
            VerificationAction::Verify => (
                Some("primary".into()),
                (Some(1), Some(1_000), Some(1_000), Some(1_000)),
                Some(OnBudgetExceeded::DispatchOriginal),
            ),
            VerificationAction::Off => (None, (None, None, None, None), None),
        };
        let definition = VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "authored/reviewer".to_string(),
            execution_kind: ExecutionKind::Coding,
            model_slots: BTreeMap::from([("primary".to_string(), slot())]),
            delegation: crate::agents::DelegationPolicy::default(),
            questions: None,
            verification: Some(VerificationPolicy {
                rules: vec![VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::ToolClass {
                            tool_class: ToolClass::ArtifactWrite,
                        }],
                        any_of: vec![],
                    },
                    action,
                    max_candidates: budgets.0,
                    max_total_tokens: budgets.1,
                    max_estimated_cost_microusd: budgets.2,
                    max_collection_millis: budgets.3,
                    adjudicator_slot: adjudicator,
                    on_budget_exceeded: on_budget,
                    ..Default::default()
                }],
            }),
        };
        definition.resolve_grant(&host()).expect("grant resolves")
    }

    async fn prepared_session(root: &std::path::Path) -> (Arc<Session>, Uuid) {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db,
                root.to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        session.set_approval_mode(crate::config::extended::ApprovalMode::Yolo);
        let created = session
            .db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        (session, created.agent_instance_id)
    }

    fn tool_ctx(
        session: Arc<Session>,
        root: &std::path::Path,
        tx: &mpsc::Sender<TurnEvent>,
        agent_instance_id: Uuid,
    ) -> ToolCtx {
        ToolCtx {
            agent_id: "Build".to_string(),
            agent_instance_id: Some(agent_instance_id),
            lock_identity: "Build".to_string(),
            write_scope: None,
            current_tool_call_id: None,
            tool_steering: crate::agents::ToolSteering::Terse,
            locks: Arc::new(crate::locks::LockManager::in_memory(session.db.clone())),
            session,
            cwd: root.to_path_buf(),
            redact: Arc::new(RedactionTable::empty()),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            interrupts: Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
            approver: None,
            image_generation_dispatch: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            root_agent_frame: true,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: None,
            available_tools: Arc::new(std::collections::HashSet::new()),
            mcp_builtin_registry: Arc::new(crate::mcp::builtin::BuiltinRegistry::default_with(
                Vec::new(),
            )),
            has_tree: false,
            has_bash: false,
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: None,
            config: crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(root),
        }
    }

    async fn dispatch_named(
        name: &str,
        grant: Option<EffectiveVnextGrant>,
    ) -> (
        bool,
        String,
        Vec<crate::db::verification_ledger::VerificationOperationRow>,
        Vec<crate::db::tool_calls::ToolCallEvent>,
        Vec<TurnEvent>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NamedFixtureTool {
            name: name.to_string(),
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone(), grant);
        let (session, instance_id) = prepared_session(tmp.path()).await;
        let model = test_model();
        let (tx, mut rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx, instance_id);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            name,
            serde_json::json!({ "path": "src/lib.rs", "content": "fn x() {}" }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        execute_ordinary_call(&env, &mut history, &call, name, Recovery::Clean, None)
            .await
            .unwrap();
        let rows = session
            .db
            .list_verification_operations_for_session(session.id)
            .await
            .unwrap();
        let tool_calls = session
            .db
            .list_tool_calls_for_session(session.id)
            .await
            .unwrap();
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        (
            called.load(Ordering::SeqCst),
            last_tool_result_text(&history),
            rows,
            tool_calls,
            events,
        )
    }

    #[tokio::test]
    async fn matching_edit_records_one_dispatch_original_row_and_executes() {
        let (called, wire, rows, _, _) =
            dispatch_named("edit", Some(verify_grant(VerificationAction::Verify))).await;
        assert!(called, "shadow mode must still execute the original edit");
        assert_eq!(wire, "applied");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].budget_action,
            Some(VerificationBudgetAction::DispatchOriginal)
        );
        assert_eq!(
            rows[0].estimate_state,
            VerificationEstimateState::EstimateUnavailable
        );
    }

    #[tokio::test]
    async fn non_matching_tool_produces_no_verification_row() {
        let (called, wire, rows, _, _) =
            dispatch_named("read", Some(verify_grant(VerificationAction::Verify))).await;
        assert!(called);
        assert_eq!(wire, "applied");
        assert!(
            rows.is_empty(),
            "unclassified tools must not write ledger rows"
        );
    }

    #[tokio::test]
    async fn off_rule_produces_no_verification_row() {
        let (called, wire, rows, _, _) =
            dispatch_named("edit", Some(verify_grant(VerificationAction::Off))).await;
        assert!(called);
        assert_eq!(wire, "applied");
        assert!(rows.is_empty(), "action off must not write ledger rows");
    }

    #[tokio::test]
    async fn no_policy_produces_no_verification_row() {
        let (called, wire, rows, _, _) = dispatch_named("edit", None).await;
        assert!(called);
        assert_eq!(wire, "applied");
        assert!(
            rows.is_empty(),
            "dispatch without a verification policy must stay ledger-silent"
        );
    }

    #[tokio::test]
    async fn unknown_price_refusal_is_terminal_and_a_failed_tool_call() {
        let mut grant = verify_grant(VerificationAction::Verify);
        grant
            .verification
            .as_mut()
            .expect("compiled verification policy")
            .regions[0]
            .rule
            .on_budget_exceeded = Some(OnBudgetExceeded::Refuse);
        let (called, wire, rows, tool_calls, events) = dispatch_named("edit", Some(grant)).await;
        assert!(!called);
        assert!(wire.contains("verification budget was exceeded"), "{wire}");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].state,
            crate::db::verification_ledger::VerificationOperationState::SkippedBudgetRefused
        );
        assert_eq!(
            rows[0].budget_action,
            Some(VerificationBudgetAction::Refuse)
        );
        assert_eq!(
            rows[0].estimate_state,
            VerificationEstimateState::EstimateUnavailable
        );
        assert_eq!(tool_calls.len(), 1);
        assert!(tool_calls[0].hard_fail);
        assert_eq!(tool_calls[0].output, wire);
        assert!(events.iter().any(|event| matches!(
            event,
            TurnEvent::ToolEnd { output, .. } if output == &wire
        )));
    }

    #[tokio::test]
    async fn verify_generators_record_candidates_then_dispatch_original() {
        crate::engine::verification::estimate::set_test_model_price(Some((0.0, 0.0)));
        crate::engine::verification::generate::set_generator_override(vec![
            crate::engine::verification::generate::GeneratorAnswer {
                kind: crate::engine::verification::generate::CandidateKind::Revision,
                args: Some(serde_json::json!({"path": "a.rs", "content": "x"})),
                critique: "x".into(),
            },
        ]);
        let definition = VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "authored/reviewer".to_string(),
            execution_kind: ExecutionKind::Coding,
            model_slots: BTreeMap::from([("primary".to_string(), slot())]),
            delegation: crate::agents::DelegationPolicy::default(),
            questions: None,
            verification: Some(VerificationPolicy {
                rules: vec![VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::ToolClass {
                            tool_class: ToolClass::ArtifactWrite,
                        }],
                        any_of: vec![],
                    },
                    action: VerificationAction::Verify,
                    adjudicator_slot: Some("primary".into()),
                    on_budget_exceeded: Some(OnBudgetExceeded::DispatchOriginal),
                    generators: vec![crate::agents::GeneratorSpec {
                        slot: "primary".into(),
                        recipe: crate::agents::VerificationRecipe::Inherit,
                        max_turns: 1,
                    }],
                    ..Default::default()
                }],
            }),
        };
        let grant = definition.resolve_grant(&host()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let tools = ToolBox::new().with(Arc::new(NamedFixtureTool {
            name: "edit".into(),
            called: called.clone(),
        }));
        let agent = test_agent(tools.clone(), Some(grant));
        let (session, instance_id) = prepared_session(tmp.path()).await;
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx, instance_id);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "edit",
            serde_json::json!({ "path": "src/lib.rs", "content": "fn x() {}" }),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        execute_ordinary_call(&env, &mut history, &call, "edit", Recovery::Clean, None)
            .await
            .unwrap();
        crate::engine::verification::generate::clear_generator_override();
        crate::engine::verification::estimate::set_test_model_price(None);
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(last_tool_result_text(&history), "applied");
        let ops = session
            .db
            .list_verification_operations_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(ops.len(), 1);
        let candidates = session
            .db
            .list_verification_candidates_for_operation(session.id, ops[0].operation_id)
            .await
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].state,
            crate::db::verification_ledger::VerificationCandidateState::Valid
        );
    }

    fn verify_grant_inheriting_cost() -> EffectiveVnextGrant {
        let definition = VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "authored/reviewer".to_string(),
            execution_kind: ExecutionKind::Coding,
            model_slots: BTreeMap::from([("primary".to_string(), slot())]),
            delegation: crate::agents::DelegationPolicy::default(),
            questions: None,
            verification: Some(VerificationPolicy {
                rules: vec![VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::ToolClass {
                            tool_class: ToolClass::ArtifactWrite,
                        }],
                        any_of: vec![],
                    },
                    action: VerificationAction::Verify,
                    adjudicator_slot: Some("primary".into()),
                    on_budget_exceeded: Some(OnBudgetExceeded::DispatchOriginal),
                    ..Default::default()
                }],
            }),
        };
        definition.resolve_grant(&host()).unwrap()
    }

    fn revise_grant() -> EffectiveVnextGrant {
        let definition = VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "authored/reviewer".to_string(),
            execution_kind: ExecutionKind::Coding,
            model_slots: BTreeMap::from([("primary".to_string(), slot())]),
            delegation: crate::agents::DelegationPolicy::default(),
            questions: None,
            verification: Some(VerificationPolicy {
                rules: vec![VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::ToolClass {
                            tool_class: ToolClass::ArtifactWrite,
                        }],
                        any_of: vec![],
                    },
                    action: VerificationAction::Verify,
                    adjudicator_slot: Some("primary".into()),
                    on_budget_exceeded: Some(OnBudgetExceeded::Refuse),
                    mode: Some(VerificationMode::Revise),
                    generators: vec![GeneratorSpec {
                        slot: "primary".into(),
                        recipe: VerificationRecipe::Inherit,
                        max_turns: 1,
                    }],
                    on_adjudication_failure: Some(OnAdjudicationFailure::DispatchOriginal),
                    ..Default::default()
                }],
            }),
        };
        definition.resolve_grant(&host()).unwrap()
    }

    #[tokio::test]
    async fn gate_block_does_not_execute_and_returns_structured_refusal() {
        crate::engine::verification::estimate::set_test_model_price(Some((0.0, 0.0)));
        crate::engine::verification::adjudicate::set_adjudicator_override(
            crate::engine::verification::adjudicate::AdjudicatorVerdict {
                decision: crate::engine::verification::adjudicate::AdjudicatorDecision::Block,
                selected: None,
                feedback: "style mismatch".into(),
            },
        );
        let (called, wire, rows, tool_calls, events) =
            dispatch_named("edit", Some(verify_grant_inheriting_cost())).await;
        crate::engine::verification::adjudicate::clear_adjudicator_override();
        crate::engine::verification::estimate::set_test_model_price(None);
        assert!(!called, "blocked verification must not execute the tool");
        assert!(
            wire.contains("verification blocked this edit: style mismatch"),
            "{wire}"
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].state,
            crate::db::verification_ledger::VerificationOperationState::Failed
        );
        assert_eq!(tool_calls.len(), 1);
        assert!(tool_calls[0].hard_fail);
        assert_eq!(tool_calls[0].output, wire);
        assert!(events.iter().any(|event| matches!(
            event,
            TurnEvent::ToolEnd { output, .. } if output == &wire
        )));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, TurnEvent::ToolError { .. }))
        );
    }

    #[tokio::test]
    async fn revise_mode_block_refuses_even_when_adjudication_failures_dispatch_original() {
        crate::engine::verification::estimate::set_test_model_price(Some((0.0, 0.0)));
        crate::engine::verification::generate::set_generator_override(vec![
            crate::engine::verification::generate::GeneratorAnswer {
                kind: crate::engine::verification::generate::CandidateKind::Revision,
                args: Some(serde_json::json!({"path": "a.rs", "content": "candidate"})),
                critique: "candidate must not override an explicit block".into(),
            },
        ]);
        crate::engine::verification::adjudicate::set_adjudicator_override(
            crate::engine::verification::adjudicate::AdjudicatorVerdict {
                decision: crate::engine::verification::adjudicate::AdjudicatorDecision::Block,
                selected: None,
                feedback: "do not apply".into(),
            },
        );
        let (called, wire, rows, tool_calls, events) =
            dispatch_named("edit", Some(revise_grant())).await;
        crate::engine::verification::adjudicate::clear_adjudicator_override();
        crate::engine::verification::generate::clear_generator_override();
        crate::engine::verification::estimate::set_test_model_price(None);

        assert!(
            !called,
            "a revise-mode block is a refusal, not an adjudication failure"
        );
        assert!(wire.contains("verification blocked this edit: do not apply"));
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].state,
            crate::db::verification_ledger::VerificationOperationState::Failed
        );
        assert_eq!(tool_calls.len(), 1);
        assert!(tool_calls[0].hard_fail);
        assert_eq!(tool_calls[0].output, wire);
        assert!(events.iter().any(|event| matches!(
            event,
            TurnEvent::ToolEnd { output, .. } if output == &wire
        )));
    }

    #[tokio::test]
    async fn selected_revision_host_failure_never_dispatches_original() {
        crate::engine::verification::estimate::set_test_model_price(Some((0.0, 0.0)));
        crate::engine::verification::generate::set_generator_override(vec![
            crate::engine::verification::generate::GeneratorAnswer {
                kind: crate::engine::verification::generate::CandidateKind::Revision,
                args: Some(serde_json::json!({"path": "a.rs", "content": "revision"})),
                critique: "selected revision".into(),
            },
        ]);
        crate::engine::verification::adjudicate::set_adjudicator_override(
            crate::engine::verification::adjudicate::AdjudicatorVerdict {
                decision: crate::engine::verification::adjudicate::AdjudicatorDecision::Select,
                selected: Some(Uuid::nil()),
                feedback: String::new(),
            },
        );
        let tmp = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let tools = ToolBox::new().with(Arc::new(RevisionFailureTool {
            calls: calls.clone(),
        }));
        let agent = test_agent(tools.clone(), Some(revise_grant()));
        let (session, instance_id) = prepared_session(tmp.path()).await;
        let model = test_model();
        let (tx, _rx) = mpsc::channel(8);
        let ctx = tool_ctx(session.clone(), tmp.path(), &tx, instance_id);
        let env = DispatchEnv {
            agent: &agent,
            session: &session,
            model: &model,
            active_tools: &tools,
            ctx: &ctx,
            tx: &tx,
            hint_corrections: false,
            loop_guard_threshold: 10,
            hooks: &crate::config::extended::hooks::HookRegistry::default(),
            cwd: tmp.path(),
        };
        let call = tool_call(
            "write",
            serde_json::json!({"path": "a.rs", "content": "original"}),
        );
        let mut history = Vec::new();
        push_assistant_call(&mut history, &call);
        execute_ordinary_call(&env, &mut history, &call, "write", Recovery::Clean, None)
            .await
            .unwrap();
        crate::engine::verification::adjudicate::clear_adjudicator_override();
        crate::engine::verification::generate::clear_generator_override();
        crate::engine::verification::estimate::set_test_model_price(None);

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            last_tool_result_text(&history).contains("selected revision failed host validation")
        );
        let operations = session
            .db
            .list_verification_operations_for_session(session.id)
            .await
            .unwrap();
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].state,
            crate::db::verification_ledger::VerificationOperationState::Failed
        );
    }
}
