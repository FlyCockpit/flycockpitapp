//! Dispatch-time verification intercept.
//!
//! Runs after arg repair, path normalization, and every human/host approval
//! gate (safety, loop, cage, /btw, pre-tool hooks) and before
//! `dispatch_one_timed`. Model-vs-model verification never sees a call an
//! approval would have killed.
//!
//! Stage 1 is shadow mode: matching `verify` rules record a
//! `verification_operations` row with `estimate_state='estimate_unavailable'`
//! and `budget_action='dispatch_original'` (no estimator yet, so every
//! `Unknown*` arm is treated as dispatch-original) then dispatch the original
//! call unchanged. Session-snapshot reduction is not applied here; the
//! compiled policy on [`crate::agents::EffectiveVnextGrant`] is the authority.
//! Snapshot-based session reduction lands with profile wiring in a later stage.

use anyhow::Result;
use serde_json::Value;
use uuid::Uuid;

use crate::agents::{
    EffectiveVnextGrant, ToolClass, VerificationAction, VerificationDispatch, VerificationEstimate,
    VerificationSessionReduction, VerificationSubject,
};
use crate::db::stats::PriceTable;
use crate::db::verification_ledger::{
    NewVerificationOperation, VerificationBudgetAction, VerificationDigest,
};
use crate::engine::agent::Agent;
use crate::engine::model::Model;
use crate::engine::tool::ToolCtx;
use crate::session::Session;

use super::adjudicate::{AdjudicatorDecision, adjudicate, apply_mode, selected_revision};
use super::budget::budget_to_ledger;
use super::classify_tool;
use super::estimate::{CandidateSetEstimateInput, encoding_for_model_id, estimate_candidate_set};
use super::generate::{CollectionInput, collect_candidates};
use super::recipe::select_guidance_for_target;

/// Outcome of the verification intercept.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VerificationOutcome {
    /// No matching verify rule, no compiled policy, or no durable agent
    /// instance. Dispatch the original call and write no ledger row.
    Skip,
    /// Matching verify rule recorded as dispatch-original. Execute the
    /// original call unchanged.
    DispatchOriginal { operation_id: Uuid },
    /// Gate mode blocked the call. Do not execute.
    Block { message: String, operation_id: Uuid },
    /// Revise mode: dispatch substituted args.
    Revise {
        args: Value,
        disclosure: String,
        operation_id: Uuid,
    },
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

/// Resolve the dispatching agent's compiled verification policy and, in
/// shadow mode, record a dispatch-original operation for matching
/// ArtifactWrite calls.
pub(crate) async fn intercept_ordinary_call(input: InterceptInput<'_>) -> VerificationOutcome {
    if let Some(payload) = crate::engine::interrupt::current_interrupt_park_payload()
        && payload.tool == input.resolved_name
        && payload.call_id == input.call_id
        && let Some(memo) = payload.verification
    {
        return match memo.outcome {
            crate::db::needs_attention::InterruptVerificationOutcome::DispatchOriginal => {
                VerificationOutcome::DispatchOriginal {
                    operation_id: memo.operation_id,
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
                operation_id: memo.operation_id,
            },
        };
    }
    let Some(tool_class) = classify_tool(input.resolved_name) else {
        return VerificationOutcome::Skip;
    };
    let Some(grant) = input.agent.vnext_grant.as_ref() else {
        return VerificationOutcome::Skip;
    };
    let Some(instance_id) = input.ctx.agent_instance_id else {
        return VerificationOutcome::Skip;
    };

    match shadow_record(input, grant, tool_class, instance_id).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(
                error = %error,
                tool = input.resolved_name,
                "verification intercept failed open; dispatching original"
            );
            VerificationOutcome::Skip
        }
    }
}

async fn shadow_record(
    input: InterceptInput<'_>,
    grant: &EffectiveVnextGrant,
    tool_class: ToolClass,
    agent_instance_id: Uuid,
) -> Result<VerificationOutcome> {
    let subject = VerificationSubject {
        tool_class,
        tool_id: input.resolved_name,
        namespace: "host",
    };
    let Some(rule) = grant
        .verification
        .as_ref()
        .and_then(|policy| policy.select(&subject))
    else {
        return Ok(VerificationOutcome::Skip);
    };
    if rule.action == VerificationAction::Off {
        return Ok(VerificationOutcome::Skip);
    }
    let requested = rule.requested_budget(grant.host_policy.verification_ceiling)?;
    let assembled = serde_json::to_string(&serde_json::json!({
        "tool": input.resolved_name,
        "args": input.args,
    }))?;
    let prices = PriceTable::load_default();
    let price = prices.get(input.model.model_id_ref());
    let pre = estimate_candidate_set(CandidateSetEstimateInput {
        assembled_texts: &[assembled.clone()],
        encoding: encoding_for_model_id(input.model.model_id_ref()),
        input_price_per_mtok: price.map(|p| p.input_per_mtok),
        output_price_per_mtok: price.map(|p| p.output_per_mtok),
        max_candidates: requested.max_candidates,
        max_collection_millis: requested.max_collection_millis,
    });
    let estimate = pre.to_verification_estimate();
    let estimate_known = matches!(estimate, VerificationEstimate::Known(_));
    let dispatch = grant.resolve_verification(
        &subject,
        VerificationSessionReduction::Inherit,
        None,
        estimate,
    )?;
    match dispatch {
        VerificationDispatch::Off => return Ok(VerificationOutcome::Skip),
        VerificationDispatch::Refuse
        | VerificationDispatch::DispatchOriginal
        | VerificationDispatch::Verify { .. } => {}
    }
    let generators = rule.generators.clone();
    let recorded_action = match dispatch {
        VerificationDispatch::Verify { .. } => None,
        VerificationDispatch::Refuse => Some(VerificationBudgetAction::Refuse),
        VerificationDispatch::DispatchOriginal => Some(VerificationBudgetAction::DispatchOriginal),
        VerificationDispatch::Off => return Ok(VerificationOutcome::Skip),
    };
    let now = chrono::Utc::now().timestamp_millis();
    let ledger = budget_to_ledger(requested);
    let generator_count = i64::try_from(generators.len()).unwrap_or(0);
    let effective_candidate_count = if recorded_action.is_some() {
        0
    } else {
        generator_count.min(ledger.candidate_count).max(0)
    };
    let original_digest = VerificationDigest::of(assembled.as_bytes());
    let pretool_digest = VerificationDigest::of(
        format!(
            "shadow-pretool:{}:{}",
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
                conservative_token_reservation: 0,
                conservative_cost_reservation_microunits: 0,
                original_operation_digest: original_digest,
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
    let mut collected = Vec::new();
    if recorded_action.is_none() && !generators.is_empty() {
        collected = collect_candidates(CollectionInput {
            session: input.session,
            agent: input.agent,
            model: input.model,
            ctx: input.ctx,
            history: input.history,
            resolved_name: input.resolved_name,
            args: input.args,
            generators: &generators,
            operation_id: created.operation_id,
            expected_revision: created.revision,
            workspace_root: input.session.project_root.as_path(),
        })
        .await
        .unwrap_or_default();
    }
    if recorded_action.is_none() {
        let names = input.ctx.config.extended().agent_guidance_files.clone();
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
            &names,
        )
        .await
        .map(|(_, body)| body)
        .unwrap_or_default();
        let verdict = adjudicate(
            input.model,
            input.args,
            &collected,
            &instructions,
            rule.resolved_on_adjudication_failure(),
        )
        .await
        .unwrap_or(super::adjudicate::AdjudicatorVerdict {
            decision: match rule.resolved_on_adjudication_failure() {
                crate::agents::OnAdjudicationFailure::Refuse => AdjudicatorDecision::Block,
                crate::agents::OnAdjudicationFailure::DispatchOriginal => {
                    AdjudicatorDecision::Approve
                }
            },
            selected: None,
            feedback: "adjudicator failed".into(),
        });
        let verdict = apply_mode(verdict, rule.resolved_mode(), &collected);
        match (rule.resolved_mode(), verdict.decision) {
            (_, AdjudicatorDecision::Approve) => {}
            (crate::agents::VerificationMode::Gate, AdjudicatorDecision::Block) => {
                let feedback = if verdict.feedback.is_empty() {
                    "verification rejected this change".to_string()
                } else {
                    verdict.feedback
                };
                return Ok(VerificationOutcome::Block {
                    message: format!(
                        "verification blocked this edit: {feedback}; revise and re-emit"
                    ),
                    operation_id: created.operation_id,
                });
            }
            (crate::agents::VerificationMode::Revise, AdjudicatorDecision::Select)
            | (crate::agents::VerificationMode::Revise, AdjudicatorDecision::Block) => {
                if let Some(answer) = selected_revision(&verdict, &collected)
                    && let Some(applied) = answer.args.clone()
                {
                    let original_call = serde_json::to_string_pretty(input.args)?;
                    let applied_call = serde_json::to_string_pretty(&applied)?;
                    let disclosure = format!(
                        "[cockpit] verification revised this change before applying:\n{}",
                        crate::engine::guidance_diff::unified_diff(&original_call, &applied_call)
                    );
                    return Ok(VerificationOutcome::Revise {
                        args: applied,
                        disclosure,
                        operation_id: created.operation_id,
                    });
                }
                let feedback = if verdict.feedback.is_empty() {
                    "verification rejected this change".to_string()
                } else {
                    verdict.feedback
                };
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
    Ok(VerificationOutcome::DispatchOriginal {
        operation_id: created.operation_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{
        ExecutionKind, ModelCapability, ModelLocality, ModelSlot, OnBudgetExceeded,
        SelectorPredicate, ToolClass, VerificationAction, VerificationPolicy, VerificationRule,
        VerificationSelector, VnextAgentDef, VnextHostPolicy,
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::mpsc;

    struct NamedFixtureTool {
        name: String,
        called: Arc<AtomicBool>,
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
        (
            called.load(Ordering::SeqCst),
            last_tool_result_text(&history),
            rows,
        )
    }

    #[tokio::test]
    async fn matching_edit_records_one_dispatch_original_row_and_executes() {
        let (called, wire, rows) =
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
        let (called, wire, rows) =
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
        let (called, wire, rows) =
            dispatch_named("edit", Some(verify_grant(VerificationAction::Off))).await;
        assert!(called);
        assert_eq!(wire, "applied");
        assert!(rows.is_empty(), "action off must not write ledger rows");
    }

    #[tokio::test]
    async fn no_policy_produces_no_verification_row() {
        let (called, wire, rows) = dispatch_named("edit", None).await;
        assert!(called);
        assert_eq!(wire, "applied");
        assert!(
            rows.is_empty(),
            "dispatch without a verification policy must stay ledger-silent"
        );
    }

    #[tokio::test]
    async fn verify_generators_record_candidates_then_dispatch_original() {
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

    #[tokio::test]
    async fn gate_block_does_not_execute_and_returns_structured_refusal() {
        crate::engine::verification::adjudicate::set_adjudicator_override(
            crate::engine::verification::adjudicate::AdjudicatorVerdict {
                decision: crate::engine::verification::adjudicate::AdjudicatorDecision::Block,
                selected: None,
                feedback: "style mismatch".into(),
            },
        );
        let (called, wire, rows) =
            dispatch_named("edit", Some(verify_grant_inheriting_cost())).await;
        crate::engine::verification::adjudicate::clear_adjudicator_override();
        assert!(!called, "blocked verification must not execute the tool");
        assert!(
            wire.contains("verification blocked this edit: style mismatch"),
            "{wire}"
        );
        assert_eq!(rows.len(), 1);
    }
}
