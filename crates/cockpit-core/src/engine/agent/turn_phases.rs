use std::ops::ControlFlow;

use super::*;

struct InferenceJournalAttempt {
    journal: Arc<crate::external_journal::ExternalJournal>,
    ticket: crate::external_journal::DispatchTicket,
}

async fn prepare_inference_journal(
    session: &Arc<Session>,
    model: &Model,
    payload: &Value,
    call_id: Uuid,
    ordinal: i64,
) -> Result<Option<InferenceJournalAttempt>> {
    let Some(journal) = session.external_journal() else {
        if session.unjournaled_inference_allowed() {
            return Ok(None);
        }
        // The durable-before-handoff barrier is a HARD invariant in every build,
        // test included: with no journal and no audited opt-out there is no way
        // to record the pending inference, so the provider handoff is refused.
        // Tests that exercise inference install a production-shaped journal via
        // the session harness (`Session::install_test_external_journal`) or take
        // the audited `allow_unjournaled_inference` opt-out.
        anyhow::bail!("inference audit journal is unavailable; provider handoff refused");
    };
    let encoded = serde_json::to_vec(payload).context("encoding redacted inference audit")?;
    let provider_identity = format!("{}:{}", model.provider_id(), model.model_id_ref());
    let projection = crate::external_journal::projection::SanitizedProjection::new(
        crate::external_journal::projection::OperationBody::InferenceRecovery {
            request_digest: crate::external_journal::projection::Digest::of(&encoded),
            provider_digest: crate::external_journal::projection::Digest::of(
                provider_identity.as_bytes(),
            ),
        },
    );
    let owner = crate::external_journal::projection::SafeToken::for_session(session.id);
    // Each dispatched-target attempt (primary, then every backup/failover step)
    // shares the logical `call_id` but carries a distinct `ordinal`. The journal
    // identity triple must therefore include the ordinal — otherwise the backup
    // attempt collides with the primary's already-settled operation and its
    // `begin_dispatch` is refused, breaking failover for every journaled session.
    let idempotency = crate::external_journal::projection::SafeToken::parse(&format!(
        "{}-{ordinal}",
        call_id.hyphenated()
    ))
    .context("building inference journal idempotency key")?;
    let now = chrono::Utc::now().timestamp_millis();
    let prepared = journal
        .prepare(&owner, &idempotency, &projection, now)
        .await
        .map_err(|_| anyhow::anyhow!("inference audit prepared commit failed"))?;
    let ticket = journal
        .begin_dispatch(prepared.operation_id, &projection, now)
        .await
        .map_err(|_| anyhow::anyhow!("inference audit dispatching commit failed"))?;
    Ok(Some(InferenceJournalAttempt { journal, ticket }))
}

async fn settle_inference_journal_success(attempt: &mut Option<InferenceJournalAttempt>) -> bool {
    let Some(attempt) = attempt else { return true };
    let now = chrono::Utc::now().timestamp_millis();
    if attempt
        .journal
        .record_outcome(
            &mut attempt.ticket,
            crate::db::external_journal::ExternalJournalState::Accepted,
            now,
        )
        .await
        .is_err()
    {
        return false;
    }
    attempt
        .journal
        .record_outcome(
            &mut attempt.ticket,
            crate::db::external_journal::ExternalJournalState::Succeeded,
            now,
        )
        .await
        .is_ok()
}

async fn settle_inference_journal_error(
    attempt: &mut Option<InferenceJournalAttempt>,
    error: &anyhow::Error,
) -> bool {
    let Some(attempt) = attempt else { return true };
    let now = chrono::Utc::now().timestamp_millis();
    if crate::engine::model::is_cancelled(error) {
        if attempt
            .journal
            .request_cancellation(attempt.ticket.operation_id, now)
            .await
            .is_err()
        {
            return false;
        }
        let state = match crate::engine::model::cancellation_phase(error) {
            Some(crate::engine::model::InferencePhase::Prep) => {
                crate::db::external_journal::ExternalJournalState::Cancelled
            }
            Some(crate::engine::model::InferencePhase::Dispatched) | None => {
                crate::db::external_journal::ExternalJournalState::SubmissionUnknown
            }
            Some(
                crate::engine::model::InferencePhase::FirstToken
                | crate::engine::model::InferencePhase::Streaming,
            ) => crate::db::external_journal::ExternalJournalState::CompletedAfterCancel,
        };
        return attempt
            .journal
            .record_outcome(&mut attempt.ticket, state, now)
            .await
            .is_ok();
    }
    let failure = crate::engine::model::as_inference_failure(error);
    let provably_unsent = crate::engine::model::is_gated(error)
        || failure.is_some_and(|failure| failure.phase == "prep");
    if provably_unsent {
        return attempt
            .journal
            .record_outcome(
                &mut attempt.ticket,
                crate::db::external_journal::ExternalJournalState::Rejected,
                now,
            )
            .await
            .is_ok();
    }
    let provider_replied = failure.is_some_and(|failure| {
        matches!(
            failure.class,
            crate::engine::model::InferenceErrorClass::Http(_)
        ) || failure.phase == crate::engine::model::InferencePhase::FirstToken.as_str()
            || failure.phase == crate::engine::model::InferencePhase::Streaming.as_str()
    });
    if provider_replied {
        if attempt
            .journal
            .record_outcome(
                &mut attempt.ticket,
                crate::db::external_journal::ExternalJournalState::Accepted,
                now,
            )
            .await
            .is_err()
        {
            return false;
        }
        attempt
            .journal
            .record_outcome(
                &mut attempt.ticket,
                crate::db::external_journal::ExternalJournalState::Failed,
                now,
            )
            .await
            .is_ok()
    } else {
        attempt
            .journal
            .record_outcome(
                &mut attempt.ticket,
                crate::db::external_journal::ExternalJournalState::SubmissionUnknown,
                now,
            )
            .await
            .is_ok()
    }
}

fn provider_error_remains_primary(error: anyhow::Error, audit_settled: bool) -> anyhow::Error {
    if !audit_settled {
        // Deliberately do not attach, format, or log the audit error here. The
        // provider error is the actionable turn failure and the secondary
        // diagnostic must be both bounded and safe for logs.
        tracing::warn!("secondary inference audit reconciliation failed");
    }
    error
}

pub(crate) struct TurnCtx<'a> {
    pub(crate) agent: &'a Agent,
    pub(crate) model: &'a Model,
    pub(crate) session: &'a Arc<Session>,
    pub(crate) locks: &'a Arc<crate::locks::LockManager>,
    pub(crate) redact: &'a Arc<RedactionTable>,
    pub(crate) cwd: &'a std::path::Path,
    /// Turn-pinned session config reader, threaded onto every `ToolCtx` this
    /// turn builds (`engine-config-snapshot-adoption`).
    pub(crate) config: &'a crate::daemon::session_worker::SessionConfigHandle,
    pub(crate) interrupts: &'a Arc<crate::engine::interrupt::InterruptHub>,
    pub(crate) cancel: &'a tokio_util::sync::CancellationToken,
    pub(crate) approver: Option<&'a Arc<crate::approval::Approver>>,
    pub(crate) lsp: Option<&'a Arc<crate::daemon::lsp::LspManager>>,
    pub(crate) resource_scheduler:
        Option<&'a Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    pub(crate) loop_guard_threshold: u32,
    pub(crate) is_root: bool,
    pub(crate) skill_write_origin: crate::skills::manage::SkillWriteOrigin,
    pub(crate) review_cage: Option<crate::engine::tool::ReviewCage>,
    pub(crate) context_usage: crate::engine::tool::ContextUsageSnapshot,
    pub(crate) deferred_log: crate::engine::deferred::DeferredLog,
    pub(crate) emit_inference_error_ui: bool,
    pub(crate) call_id: Uuid,
    /// Dispatched-target attempt index for the immutable per-attempt inference
    /// log: 0 for the primary path that bypasses `turn_with_backup`; the backup
    /// loop threads incrementing ordinals sharing the logical `call_id`.
    pub(crate) ordinal: i64,
    pub(crate) tandem: Option<&'a crate::engine::schedule::TandemSet>,
    pub(crate) goal_provenance: Option<(Uuid, i64)>,
    pub(crate) turn_id: Option<String>,
    pub(crate) tx: &'a mpsc::Sender<TurnEvent>,
    pub(crate) display_slot: Option<crate::engine::model::DisplayAttemptSlot>,
}

pub(crate) fn phase_01_pre_send_history_mutation() {}
pub(crate) fn phase_02_dispatch_time_record() {}
pub(crate) fn phase_03_tandem_shadow_dispatch() {}
pub(crate) fn phase_04_inference_call() {}
pub(crate) fn phase_05_settle_completed_record() {}
pub(crate) fn phase_06_post_inference_text_processing() {}
pub(crate) fn phase_07_history_push() {}
pub(crate) fn phase_08_text_embedded_tool_call_recovery() {}
pub(crate) fn phase_09_terminal_text_emit() {}

pub(crate) fn new_display_attempt_slot(
    session: &Arc<Session>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
) -> crate::engine::model::DisplayAttemptSlot {
    crate::engine::model::DisplayAttemptSlot::new(crate::engine::DisplayClassifierConfig {
        inline_think: inline_think_enabled(session, config),
        translation_enabled: config.extended().translation.is_active(),
        encoding: config.extended().response_metrics_tokenizer,
        force_tokenization_failure: false,
    })
}

async fn record_task_unknown_agent_rejection(session: &Arc<Session>, agent: &Agent, tc: &ToolCall) {
    if let Err(e) = session
        .record_tool_rejected(&agent.name, &tc.id, "task", "task_unknown_agent")
        .await
    {
        tracing::warn!(error = %e, tool = "task", "record tool_rejected event failed");
    }
}

async fn fork_context_refusal(
    session: &Arc<Session>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    parent: &Agent,
    child: &str,
    prompt: &str,
    model: &Option<crate::engine::model_roles::DelegationModelSelector>,
    noninteractive: bool,
) -> Option<String> {
    if !crate::engine::tool::Capability::ForkContext.enabled(parent.llm_mode) {
        return Some(
            "Error: task context `fork` is only available in frontier LLM mode".to_string(),
        );
    }
    if child != parent.name {
        return Some(format!(
            "Error: task context `fork` must target the delegating agent `{}`; got `{child}`",
            parent.name
        ));
    }
    if model.is_some() {
        return Some(
            "Error: task context `fork` cannot specify `model`; omit `model` so the fork keeps the parent model".to_string(),
        );
    }
    if !noninteractive {
        return Some("Error: task context `fork` must resolve noninteractively; use mode `subagent` or omit interactive routing".to_string());
    }
    if prompt_has_redundant_seed_tag(prompt) {
        return Some(
            "Error: task context `fork` already inherits the parent transcript; remove @file/@dir/ and /skill seed tags from the steering prompt".to_string(),
        );
    }
    match crate::agents::resolve_with_assistant_db(&session.project_root, child, &session.db).await
    {
        Ok(Some(def)) if def.fork_eligible => None,
        Ok(Some(_)) => Some(format!(
            "Error: agent `{child}` is not fork eligible; set `forkEligible: true` in its agent frontmatter to allow `task.context=\"fork\"`"
        )),
        Ok(None) => {
            let reachable = crate::engine::builtin::reachable_subagent_names(
                &parent.name,
                config,
                &session.project_root,
                &session.db,
            )
            .await;
            if reachable.is_empty() {
                Some(format!(
                    "Error: unknown agent `{child}`, and no subagents are reachable from `{}`",
                    parent.name
                ))
            } else {
                Some(format!(
                    "Error: unknown agent `{child}`. Reachable agents from `{}`: {}",
                    parent.name,
                    reachable.join(", ")
                ))
            }
        }
        Err(err) => Some(format!(
            "Error: failed to load fork agent `{child}`: {err:#}"
        )),
    }
}

fn prompt_has_redundant_seed_tag(prompt: &str) -> bool {
    prompt
        .split_whitespace()
        .any(|token| token.starts_with('@') || token.starts_with("/skill"))
}

pub(crate) async fn phase_10_dispatch_one_call(
    agent: &Agent,
    session: &Arc<Session>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    tx: &mpsc::Sender<TurnEvent>,
    tc: &ToolCall,
    resolved_name: &str,
) -> Result<ControlFlow<TurnOutcome, ()>> {
    macro_rules! return_structural {
        ($outcome:expr) => {
            return Ok(ControlFlow::Break($outcome));
        };
    }
    // `task` is special — it's a structural tool the driver
    // handles. For interactive subagents (builder) the driver
    // performs a primary handoff via [`TurnOutcome::SpawnSubagent`];
    // for noninteractive ones (explore) it runs the child inline
    // and returns the result as this task call's tool_result via
    // [`TurnOutcome::SpawnNoninteractive`]. Other tool calls in
    // the same assistant turn are dropped — the model will re-
    // emit them on the next turn once it has the task result.
    if resolved_name == "task" {
        let known_task_call_ids = match session.db.list_task_delegation_children(session.id).await {
            Ok(rows) => rows
                .into_iter()
                .map(|row| row.task_call_id)
                .collect::<std::collections::BTreeSet<_>>(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    tool = "task",
                    "load task delegation ids for fresh/control repair failed"
                );
                std::collections::BTreeSet::new()
            }
        };
        let parsed = match crate::tools::task_repair::parse_task_args(
            &tc.function.arguments,
            &known_task_call_ids,
        ) {
            Ok(parsed) => parsed,
            Err(err) => {
                if let Err(e) = session
                    .record_tool_rejected(&agent.name, &tc.id, "task", "task_intent_parse_failed")
                    .await
                {
                    tracing::warn!(error = %e, tool = "task", "record tool_rejected event failed");
                }
                return_structural!(task_refusal(
                    &tc.id,
                    tc.provider
                        .as_ref()
                        .and_then(|provider| provider.item_id.clone()),
                    tc.provider
                        .as_ref()
                        .map(|provider| provider.call_id.clone()),
                    err.model_message(),
                ));
            }
        };
        if !parsed.notes().is_empty() {
            tracing::info!(
                tool = "task",
                repair_kind = "task_intent_canonicalized",
                notes = ?parsed.notes(),
                "task arguments canonicalized"
            );
        }
        match parsed {
            crate::tools::task_repair::ParsedTaskArgs::Control {
                intent, control, ..
            } => {
                let action = match intent {
                    crate::tools::task_repair::TaskControlIntent::Models => {
                        TaskControlAction::Models
                    }
                    crate::tools::task_repair::TaskControlIntent::List => TaskControlAction::List,
                    crate::tools::task_repair::TaskControlIntent::Status => {
                        TaskControlAction::Status
                    }
                    crate::tools::task_repair::TaskControlIntent::Cancel => {
                        TaskControlAction::Cancel
                    }
                    crate::tools::task_repair::TaskControlIntent::Query => TaskControlAction::Query,
                    crate::tools::task_repair::TaskControlIntent::Steer => TaskControlAction::Steer,
                };
                let target_task_call_id = control
                    .get("task_call_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let label = control
                    .get("label")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let message = control
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                return_structural!(TurnOutcome::TaskControl {
                    action,
                    target_task_call_id,
                    label,
                    message,
                    task_call_id: tc.id.to_string(),
                    task_provider_item_id: tc
                        .provider
                        .as_ref()
                        .and_then(|provider| provider.item_id.clone()),
                    task_function_call_id: tc
                        .provider
                        .as_ref()
                        .map(|provider| provider.call_id.clone()),
                });
            }
            crate::tools::task_repair::ParsedTaskArgs::Batch {
                entries: items,
                why,
                notes: repair_notes,
            } => {
                let max_parallel = config.extended().delegation.max_parallel.max(1);
                if items.is_empty() || items.len() > max_parallel {
                    return_structural!(task_refusal(
                        &tc.id,
                        tc.provider
                            .as_ref()
                            .and_then(|provider| provider.item_id.clone()),
                        tc.provider
                            .as_ref()
                            .map(|provider| provider.call_id.clone()),
                        format!("`batch` must contain 1 to {max_parallel} entries"),
                    ));
                }
                let mut labels = std::collections::HashSet::new();
                let mut entries = Vec::new();
                for item in &items {
                    if item.get("mode").is_some() {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            "`mode` is not supported inside `batch[]`",
                        ));
                    }
                    let child = item
                        .get("agent")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("");
                    let prompt = item
                        .get("prompt")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("");
                    if child.is_empty() || prompt.is_empty() {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            "`batch[]` entries require `agent` and non-empty `prompt`",
                        ));
                    }
                    let context = TaskContext::from_value(item.get("context"));
                    let label = item
                        .get("label")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            if items.len() == 1 {
                                child.to_string()
                            } else {
                                String::new()
                            }
                        });
                    if label.is_empty() {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            "`label` is required when `batch` contains more than one entry",
                        ));
                    }
                    if !labels.insert(label.clone()) {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            format!("duplicate batch label `{label}`"),
                        ));
                    }
                    let cwd = item
                        .get("cwd")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    if agent.vnext_grant.is_none()
                        && context == TaskContext::Fresh
                        && cwd.is_none()
                        && let Some(message) = crate::engine::builtin::unknown_agent_rejection(
                            &session.project_root,
                            config,
                            &agent.name,
                            child,
                            &session.db,
                        )
                        .await
                    {
                        record_task_unknown_agent_rejection(session, agent, tc).await;
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            format!("batch entry `{label}`: {message}"),
                        ));
                    }
                    if agent.vnext_grant.is_none()
                        && !crate::engine::builtin::is_noninteractive(child)
                    {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            format!("batch entry `{label}` targets interactive agent `{child}`"),
                        ));
                    }
                    let model =
                        match crate::engine::model_roles::DelegationModelSelector::from_value(
                            item.get("model"),
                        ) {
                            Ok(model) => model,
                            Err(err) => {
                                return_structural!(task_refusal(
                                    &tc.id,
                                    tc.provider
                                        .as_ref()
                                        .and_then(|provider| provider.item_id.clone()),
                                    tc.provider
                                        .as_ref()
                                        .map(|provider| provider.call_id.clone()),
                                    format!(
                                        "batch entry `{label}` has invalid model selector: {err}"
                                    ),
                                ));
                            }
                        };
                    let resume_handle = item
                        .get("resume_handle")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    if context == TaskContext::Fork
                        && let Some(err) = fork_context_refusal(
                            session, config, agent, child, prompt, &model, true,
                        )
                        .await
                    {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            format!("batch entry `{label}`: {err}"),
                        ));
                    }
                    let remaining_depth = match task_remaining_depth(item) {
                        Ok(depth) => depth,
                        Err(err) => {
                            return_structural!(task_refusal(
                                &tc.id,
                                tc.provider
                                    .as_ref()
                                    .and_then(|provider| provider.item_id.clone()),
                                tc.provider
                                    .as_ref()
                                    .map(|provider| provider.call_id.clone()),
                                format!("batch entry `{label}` has invalid depth: {err}"),
                            ));
                        }
                    };
                    let write_scope = item
                        .get("write_scope")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    let depends_on = match item.get("depends_on") {
                        None => Vec::new(),
                        Some(Value::Array(values)) => {
                            let mut dependencies = Vec::with_capacity(values.len());
                            for value in values {
                                let Some(dependency_label) = value.as_str().map(str::trim) else {
                                    return_structural!(task_refusal(
                                        &tc.id,
                                        tc.provider
                                            .as_ref()
                                            .and_then(|provider| provider.item_id.clone()),
                                        tc.provider
                                            .as_ref()
                                            .map(|provider| provider.call_id.clone()),
                                        format!(
                                            "batch entry `{label}` has non-string `depends_on` item"
                                        ),
                                    ));
                                };
                                if dependency_label.is_empty() {
                                    return_structural!(task_refusal(
                                        &tc.id,
                                        tc.provider
                                            .as_ref()
                                            .and_then(|provider| provider.item_id.clone()),
                                        tc.provider
                                            .as_ref()
                                            .map(|provider| provider.call_id.clone()),
                                        format!(
                                            "batch entry `{label}` has empty `depends_on` label"
                                        ),
                                    ));
                                }
                                dependencies.push(dependency_label.to_string());
                            }
                            dependencies
                        }
                        Some(_) => {
                            return_structural!(task_refusal(
                                &tc.id,
                                tc.provider
                                    .as_ref()
                                    .and_then(|provider| provider.item_id.clone()),
                                tc.provider
                                    .as_ref()
                                    .map(|provider| provider.call_id.clone()),
                                format!("batch entry `{label}` requires array `depends_on`"),
                            ));
                        }
                    };
                    entries.push(BatchTaskEntry {
                        label,
                        depends_on,
                        child_agent: child.to_string(),
                        prompt: prompt.to_string(),
                        model,
                        remaining_depth,
                        resume_handle,
                        cwd,
                        context,
                        granted_tools: task_string_array(item, "grant_tools"),
                        todo_ids: task_todo_ids(item),
                        write_scope,
                    });
                }
                if let Err(error) = validate_batch_dependencies(&entries) {
                    return_structural!(task_refusal(
                        &tc.id,
                        tc.provider
                            .as_ref()
                            .and_then(|provider| provider.item_id.clone()),
                        tc.provider
                            .as_ref()
                            .map(|provider| provider.call_id.clone()),
                        error,
                    ));
                }
                return_structural!(TurnOutcome::SpawnNoninteractiveBatch {
                    entries,
                    why,
                    repair_notes,
                    task_call_id: tc.id.to_string(),
                    task_provider_item_id: tc
                        .provider
                        .as_ref()
                        .and_then(|provider| provider.item_id.clone()),
                    task_function_call_id: tc
                        .provider
                        .as_ref()
                        .map(|provider| provider.call_id.clone()),
                });
            }
            crate::tools::task_repair::ParsedTaskArgs::Delegate {
                args,
                notes: repair_notes,
            } => {
                let prompt = args
                    .get("prompt")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let child = args
                    .get("agent")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or("builder")
                    .to_string();
                // Re-queryable-subagent fields (GOALS §3c). Both are present in the
                // `task` schema from session start (cache-safe fixed shape); the
                // capability is gated behaviorally in the driver, not here.
                let why = args
                    .get("why")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let resume_handle = args
                    .get("resume_handle")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let cwd = args
                    .get("cwd")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let write_scope = args
                    .get("write_scope")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let context = TaskContext::from_value(args.get("context"));
                if agent.vnext_grant.is_none()
                    && context == TaskContext::Fresh
                    && cwd.is_none()
                    && let Some(message) = crate::engine::builtin::unknown_agent_rejection(
                        &session.project_root,
                        config,
                        &agent.name,
                        &child,
                        &session.db,
                    )
                    .await
                {
                    record_task_unknown_agent_rejection(session, agent, tc).await;
                    return_structural!(task_refusal(
                        &tc.id,
                        tc.provider
                            .as_ref()
                            .and_then(|provider| provider.item_id.clone()),
                        tc.provider
                            .as_ref()
                            .map(|provider| provider.call_id.clone()),
                        message
                    ));
                }
                let mode = args.get("mode").and_then(Value::as_str);
                let model = match crate::engine::model_roles::DelegationModelSelector::from_value(
                    args.get("model"),
                ) {
                    Ok(model) => model,
                    Err(err) => {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            format!("invalid model selector: {err}"),
                        ));
                    }
                };
                // A vNext tree uses the structural noninteractive task path.
                // That path carries the requested cwd and write_scope through
                // every recursive launch and applies the live grant against
                // the resolved target.  The legacy interactive handoff loses
                // those authority inputs, so it is not a vNext runtime path.
                let noninteractive = agent.vnext_grant.is_some()
                    || resolve_interactivity(mode, &child, resume_handle.is_some());
                if context == TaskContext::Fork
                    && let Some(err) = fork_context_refusal(
                        session,
                        config,
                        agent,
                        &child,
                        &prompt,
                        &model,
                        noninteractive,
                    )
                    .await
                {
                    return_structural!(task_refusal(
                        &tc.id,
                        tc.provider
                            .as_ref()
                            .and_then(|provider| provider.item_id.clone()),
                        tc.provider
                            .as_ref()
                            .map(|provider| provider.call_id.clone()),
                        err
                    ));
                }
                let remaining_depth = match task_remaining_depth(&args) {
                    Ok(depth) => depth,
                    Err(err) => {
                        return_structural!(task_refusal(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.clone()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.clone()),
                            err
                        ));
                    }
                };
                // Per-delegation tool grants (`task.grant_tools`, prompt
                // `parent-granted-tools.md`): the parent may attach extra tools to
                // this one delegation. Present in the `task` schema from session
                // start (cache-safe fixed shape); the driver validates each grant
                // against the target's role invariants before building the child.
                // Collected loosely here (trimmed, de-blanked, de-duplicated);
                // role-invariant rejection happens at the single driver chokepoint.
                let granted_tools = task_string_array(&args, "grant_tools");
                let todo_ids = task_todo_ids(&args);
                if !noninteractive {
                    // Timeline event (Part B): an interactive `task`
                    // delegation spawned a child. Noninteractive children
                    // are recorded by the driver after cwd validation.
                    let task_identity =
                        crate::engine::task_identity::TaskProviderIdentity::for_task_call(
                            &tc.id,
                            tc.provider
                                .as_ref()
                                .and_then(|provider| provider.item_id.as_deref()),
                            tc.provider
                                .as_ref()
                                .map(|provider| provider.call_id.as_str()),
                        );
                    let routing = agent.model.routing_metadata_json(None);
                    // This event embeds the parent model's task `prompt`
                    // (model-authored free text that can carry a session-table
                    // literal), so route it through the frame-carrying journaling
                    // path with the SPAWNING model's trust + pre-policy session
                    // table (mirrors the SubagentReport fix and this turn's
                    // inference journaling above). The spawning model is
                    // `agent.model`; its pre-policy table is
                    // `agent.model.session_redact_table()` (the same table used
                    // for this turn's inference journaling). A frame-less
                    // `record_event` skips trusted journaling, so a session-table
                    // literal in a trusted parent's prompt would persist raw with
                    // no history row; an untrusted spawning model journals
                    // nothing (payload already post-redaction).
                    let spawn_session_table = agent.model.session_redact_table();
                    if let Err(e) = session
                        .record_event_with_model_frame(
                            crate::db::session_log::SessionEventKind::SubagentSpawned,
                            Some(&agent.name),
                            Some(&tc.id),
                            crate::session::SessionEventModelFrame {
                                provider_id: agent.model.provider_id(),
                                model_id: agent.model.model_id_ref(),
                                config,
                                session_table: spawn_session_table.as_ref(),
                            },
                            &serde_json::json!({
                                "child_agent": child,
                                "task_call_id": tc.id,
                                "provider_item_id": task_identity.provider_item_id,
                                "provider_call_id": task_identity.provider_call_id,
                                "provider_call_id_source": task_identity.provider_call_id_source,
                                "provider_identity": task_identity.event_identity_json(&tc.id),
                                "label": "default",
                                "noninteractive": false,
                                "prompt": prompt,
                                "mode": mode,
                                "model": model.as_ref().map(|selector| selector.to_json()),
                                "model_trusted": agent.model.is_trusted(),
                                "routing": routing.clone(),
                                "remaining_depth": remaining_depth,
                                "why": why,
                                "resume_handle": resume_handle.clone(),
                                "grant_tools": granted_tools.clone(),
                                "todo_ids": todo_ids.clone(),
                            }),
                        )
                        .await
                    {
                        tracing::warn!(error = %e, "record subagent_spawned event failed");
                    }
                    let _ = tx
                        .send(TurnEvent::SubagentSpawned {
                            parent: agent.name.clone(),
                            child: child.clone(),
                            task_call_id: tc.id.to_string(),
                            label: "default".to_string(),
                            prompt: prompt.clone(),
                            requested_cwd: None,
                            resolved_cwd: None,
                            model_trusted: agent.model.is_trusted(),
                            routing,
                        })
                        .await;
                    return_structural!(TurnOutcome::SpawnSubagent {
                        child_agent: child,
                        prompt,
                        model,
                        remaining_depth,
                        granted_tools,
                        todo_ids,
                        repair_notes,
                        task_call_id: tc.id.to_string(),
                        task_provider_item_id: tc
                            .provider
                            .as_ref()
                            .and_then(|provider| provider.item_id.clone()),
                        task_function_call_id: tc
                            .provider
                            .as_ref()
                            .map(|provider| provider.call_id.clone()),
                    });
                }
                return_structural!(TurnOutcome::SpawnNoninteractive {
                    child_agent: child,
                    prompt,
                    model,
                    remaining_depth,
                    why,
                    resume_handle,
                    cwd,
                    write_scope,
                    context,
                    granted_tools,
                    todo_ids,
                    repair_notes,
                    task_call_id: tc.id.to_string(),
                    task_provider_item_id: tc
                        .provider
                        .as_ref()
                        .and_then(|provider| provider.item_id.clone()),
                    task_function_call_id: tc
                        .provider
                        .as_ref()
                        .map(|provider| provider.call_id.clone()),
                });
            }
        }
    }

    // `schedule` is structural in the **main** conversation: the driver
    // owns the single async-job authority (GOALS §22), so the action
    // is routed there via [`TurnOutcome::ScheduleAction`]. Inside an
    // ephemeral-fork loop iteration the toolbox instead carries the
    // in-process `ForkScheduleTool` (alongside `note`) — there, `schedule`
    // is dispatched normally and re-routes create-actions to requests
    // (forks cannot spawn scheduled work). We tell the two apart by the
    // fork-only `note` tool: present only inside a loop fork.
    if resolved_name == "schedule" && agent.tools.get("note").is_none() {
        let original_args = tc.function.arguments.clone();
        let mut args = tc.function.arguments.clone();
        // Validate + repair the loose outer object against the `schedule`
        // tool's own minimal `{action, args}` schema; per-action
        // validation runs in the driver through the same repair
        // contract (§12). The outer schema is permissive (`args` is a
        // free-form object), so this only catches a malformed `action`.
        let schedule_schema = agent
            .tools
            .get("schedule")
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let recovery = repair(&mut args, &schedule_schema, "schedule").recovery;
        return_structural!(TurnOutcome::ScheduleAction {
            original_args,
            args,
            recovery,
            task_call_id: tc.id.to_string(),
            task_provider_item_id: tc
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.clone()),
            task_function_call_id: tc
                .provider
                .as_ref()
                .map(|provider| provider.call_id.clone()),
        });
    }

    // `spawn` is structural: the driver routes the spawn to the
    // single async-job authority (GOALS §22/§24), which enforces the depth
    // ceiling + global concurrency cap and schedules the child `Swarm`
    // subagent as a parallel background job. Only `Swarm` holds it.
    if resolved_name == "spawn" {
        let schema = agent
            .tools
            .get("spawn")
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let mut args = tc.function.arguments.clone();
        let _ = repair(&mut args, &schema, "spawn");
        let prompt = args
            .get("prompt")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let write_scope = args
            .get("write_scope")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let model = args
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        return_structural!(TurnOutcome::Spawn {
            prompt,
            write_scope,
            model,
            task_call_id: tc.id.to_string(),
            task_provider_item_id: tc
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.clone()),
            task_function_call_id: tc
                .provider
                .as_ref()
                .map(|provider| provider.call_id.clone()),
        });
    }

    // `return` is structural: a delegated subagent finishes by reporting a
    // structured summary to its caller. The driver assembles the envelope
    // (model fields + host-derived `files_changed`) and injects it as the
    // delegation's tool result. Validate-then-repair the fields against the
    // tool's own schema (§12) so a weak model's loose object still yields a
    // well-formed envelope; an unparseable field defaults to empty in
    // [`crate::engine::envelope::Envelope::from_return_args`].
    if resolved_name == "return" {
        let schema = agent
            .tools
            .get("return")
            .map(|t| t.parameters())
            .unwrap_or(Value::Null);
        let mut fields = tc.function.arguments.clone();
        let _ = repair(&mut fields, &schema, "return");
        return_structural!(TurnOutcome::Return { fields });
    }

    Ok(ControlFlow::Continue(()))
}

/// Structural calls return to the driver before ordinary-tool dispatch gets a
/// chance to repair the just-stored assistant history. Keep their replay form
/// aligned with the canonical structural result name while preserving both
/// call identities for result correlation.
fn rewrite_structural_call_name_if_repaired(
    history: &mut [Message],
    tc: &ToolCall,
    resolved_name: &str,
    recovery: &Recovery,
) {
    if matches!(recovery, Recovery::NameRepair { .. }) {
        super::rewrite_assistant_tool_call_name(history, &tc.id, resolved_name);
    }
}

pub(crate) async fn run_turn(
    ctx: TurnCtx<'_>,
    history: &mut Vec<Message>,
    prompt: Message,
) -> Result<TurnOutcome> {
    let agent = ctx.agent;
    let model = ctx.model;
    let session = Arc::clone(ctx.session);
    let locks = Arc::clone(ctx.locks);
    let redact = Arc::clone(ctx.redact);
    let cwd = ctx.cwd.to_path_buf();
    let config = ctx.config.clone();
    let interrupts = Arc::clone(ctx.interrupts);
    let cancel = ctx.cancel.clone();
    let approver = ctx.approver.cloned();
    let lsp = ctx.lsp.cloned();
    let resource_scheduler = ctx.resource_scheduler.cloned();
    let loop_guard_threshold = ctx.loop_guard_threshold;
    let is_root = ctx.is_root;
    let skill_write_origin = ctx.skill_write_origin;
    let review_cage = ctx.review_cage;
    let context_usage = ctx.context_usage;
    let deferred_log = ctx.deferred_log;
    let emit_inference_error_ui = ctx.emit_inference_error_ui;
    let call_id = ctx.call_id;
    let ordinal = ctx.ordinal;
    let tandem = ctx.tandem;
    let goal_provenance = ctx.goal_provenance;
    let turn_id = ctx.turn_id;
    let tx = ctx.tx;
    let shared_display_slot = ctx.display_slot;

    phase_01_pre_send_history_mutation();
    phase_02_dispatch_time_record();
    phase_03_tandem_shadow_dispatch();
    phase_04_inference_call();
    phase_05_settle_completed_record();
    phase_06_post_inference_text_processing();
    phase_07_history_push();
    phase_08_text_embedded_tool_call_recovery();
    phase_09_terminal_text_emit();

    let active_tools = turn_toolbox(agent, &session, &cwd, &config).await;
    let mut tools = active_tools.definitions(agent.llm_mode);
    // Leak-report route gate (AC3 + AC1's buffered-delivery gate). A supported,
    // untrusted, tool-capable completion route advertises `report_leak`
    // (schema-only — NEVER a generic `Tool`; the sensitive-turn barrier
    // intercepts the call before generic dispatch) AND withholds this turn's
    // pre-classification stream deltas through the buffered delivery sink. The
    // SAME predicate drives both so schema advertisement and stream withholding
    // cannot drift. Computed on the pre-append tool set: a trusted or
    // tool-disabled (empty `tools`) route is never eligible.
    let report_leak_eligible =
        crate::leak_report::route_advertises_report_leak(model.is_trusted(), &tools);
    if report_leak_eligible {
        tools.push(crate::leak_report::report_leak_tool_definition());
    }

    inject_turn_start_system_messages(&session, &active_tools, is_root, context_usage, history)
        .await;
    let active_tool_names = active_tools.names();
    super::inject_available_skills_catalog(history, &cwd, &config, &active_tool_names);

    // Tell the TUI we've called the model — `Thinking…` shows until the
    // first AssistantTextDelta arrives.
    let _ = tx
        .send(TurnEvent::ThinkingStarted {
            agent: agent.name.clone(),
            turn_id,
        })
        .await;

    // Stamp the send time for the cache-cold predicate's TTL arm
    // (GOALS §10). Done right before the round-trip so "time since last
    // send" measures from when the provider last saw (and cached) the
    // prefix.
    session.note_send();

    inject_initial_project_guidance(&agent.name, history, &cwd, &config, redact.clone(), tx).await;
    let knowledge_query = crate::knowledge::retrieval_query_from_turn(history, &prompt);
    crate::knowledge::inject_knowledge_for_turn(
        history,
        &session,
        &cwd,
        &config,
        &knowledge_query,
        redact.clone(),
    )
    .await;

    // Live instructions-file diff injection (prompt
    // `instructions-file-live-diff.md`). Guidance now rides as user-role
    // project notes rather than raw system text, so live in-place edits do the
    // same. Gated to the session root: subagents inject their own current
    // guidance once when their first model turn starts. The baseline advances
    // on inject, so each distinct change is injected exactly once.
    if is_root && let Some(message) = session.guidance_change_injection(&cwd).await {
        inject_live_project_guidance_change(history, &cwd, &config, redact.clone(), tx, &message)
            .await;
    }

    // Live pre-send pairing heal (implementation note).
    // The history sent to the provider must never carry an orphan `tool_use`
    // (a tool call with no matching `tool_result`) — strict providers 400 on
    // it. A structural tool (`task`/`spawn`/`done`/`schedule`/`return`)
    // returns early from the dispatch loop, so any sibling `tool_use` in the
    // same assistant turn never gets a result and lingers as an orphan in
    // `history`. We heal it here, immediately before the request is assembled,
    // using the SAME helper the resume path uses (single source of truth).
    // `prompt` is the not-yet-pushed message that follows `history` on the
    // wire (the user message, or — after a structural tool — that tool's own
    // driver-injected `tool_result`), so naming its result ids keeps the
    // structural tool's pending result from being double-stubbed. A no-op
    // (no allocation, no heal) on the already-paired common path. A heal is a
    // rare backstop (the dispatch loop normally pairs every call), so it is
    // surfaced via a warn log rather than a durable row — the stubbed result is
    // a synthetic wire-only artifact, never part of the persisted transcript
    // (which records each real call's own result), so it must not enter the
    // session log lest it pollute rehydration's pairing rebuild.
    for heal in crate::engine::rehydrate::heal_live_history(history, &prompt) {
        if let crate::db::tool_calls::Recovery::ResumeHeal { kind, id } = heal {
            tracing::warn!(
                agent = %agent.name,
                kind = %kind,
                call_id = %id,
                "live pre-send heal stubbed/dropped an orphan tool pairing"
            );
        }
    }

    let endpoint_recovery =
        interrupts
            .is_interactive_attached()
            .then(|| crate::engine::model::EndpointRecoveryContext {
                approve: {
                    let session = session.clone();
                    let interrupts = interrupts.clone();
                    let agent_name = agent.name.clone();
                    std::sync::Arc::new(move |prompt| {
                        let session = session.clone();
                        let interrupts = interrupts.clone();
                        let agent_name = agent_name.clone();
                        Box::pin(async move {
                            const ID_TRY: &str = "try_alternate";
                            const ID_CANCEL: &str = "cancel";
                            let label = |wire_api| match wire_api {
                                crate::config::providers::WireApi::Completions => {
                                    "Chat Completions"
                                }
                                crate::config::providers::WireApi::Responses => "Responses",
                                crate::config::providers::WireApi::Auto => "auto",
                            };
                            let set = crate::daemon::proto::InterruptQuestionSet {
                                questions: vec![crate::daemon::proto::InterruptQuestion::Single {
                                    prompt: format!(
                                        "`{}/{}` failed on the {} endpoint. Try {} instead?",
                                        prompt.provider,
                                        prompt.model,
                                        label(prompt.attempted),
                                        label(prompt.alternate)
                                    ),
                                    options: vec![
                                        crate::daemon::proto::InterruptOption {
                                            id: ID_TRY.to_string(),
                                            label: format!("Try {}", label(prompt.alternate)),
                                            description: Some(
                                                "Retries this turn on the alternate endpoint and saves it if successful."
                                                    .to_string(),
                                            ),
                                            secondary: false,
},
                                        crate::daemon::proto::InterruptOption {
                                            id: ID_CANCEL.to_string(),
                                            label: "Cancel".to_string(),
                                            description: Some(
                                                "Surface the endpoint mismatch without retrying."
                                                    .to_string(),
                                            ),
                                            secondary: false,
},
                                    ],
                                    allow_freetext: false,
                                    command_detail: None,
                                    permission: false,
                                    approval_class: None,
                                    sandbox_escalation: None,
                                }],
                            };
                            let outcome = crate::engine::interrupt::raise_and_wait(
                                &session.db,
                                &interrupts,
                                session.id,
                                &agent_name,
                                "OpenAI-compatible endpoint recovery",
                                set,
                                "endpoint recovery",
                            )
                            .await;
                            let crate::engine::interrupt::InterruptOutcome::Resolved(response) =
                                outcome
                            else {
                                // This endpoint-recovery prompt runs before a tool dispatch
                                // result exists. Parking just declines this optional retry;
                                // it must not fabricate a ResolveResponse::Cancel.
                                return false;
                            };
                            crate::engine::interrupt::selected_id_of(&response).as_deref()
                                == Some(ID_TRY)
                        })
                            as futures::future::BoxFuture<'static, bool>
                    })
                },
            });

    // Dispatch-time recording (`inference-timeout-and-failure-
    // observability.md` #4): persist the attempt's captured body BEFORE the
    // call returns, with status `pending`, so a hung or failed turn still
    // exports an inference record instead of an empty export. The same
    // `call_id` keys the terminal update below. The timeline EVENT is recorded
    // once on settle (the `inference_request` event on success, the
    // `inference_failure` event on failure) — both carry this `call_id`, so the
    // export's file-per-call pass picks up the record either way without
    // double-counting. Best-effort: auditing must never break a live turn (same
    // posture as the existing post-success write).
    // Sealed marker wired to real grants (`sealed-value-untrusted-inference-
    // marker`): derive the per-attempt egress table so that a sealed literal an
    // untrusted interactive turn received renders the actionable
    // `use_sealed_value` marker instead of the generic placeholder. All gating
    // and derivation live in ONE production seam
    // (`derive_untrusted_interactive_sealed_egress`, extracted so the chokepoint
    // is drivable end-to-end in tests — removing the derivation there fails a
    // test): it fires ONLY when untrusted custody, an interactive attachment, a
    // callable `use_sealed_value` in THIS request's tool roster, and a live exact
    // grant for that value in this session generation all hold. Derivation is
    // fresh per attempt (a grant revoked between primary and failover renders the
    // marker then generic), the `Model` never gets a DB handle (we derive here
    // and pass the table to `prepare_completion_request`), and a DB error falls
    // back to `None` / the generic table — fail closed to safe rendering, never
    // to a stale marker, a raw literal, or a dispatch error. Trusted targets and
    // noninteractive egress (utility/tandem/embeddings, which never reach here)
    // are untouched.
    // Rebuild the live sealed-action registry from this session's database,
    // scoped to this session's project (no install-once OnceLock; cross-project
    // actions are never resolvable). A build failure falls back to an empty
    // registry — fail closed to "no callable actions", never a stale or bogus one.
    let registry = crate::sealed::action_admin::build_live_registry(
        &session.db,
        crate::sealed::identity::SealedProjectKey::from_canonical(session.project_id.clone())
            .as_str(),
    )
    .await
    .unwrap_or_else(|_| crate::sealed::action::SealedActionRegistry::empty());
    let sealed_egress: Option<Arc<RedactionTable>> =
        crate::sealed::egress::derive_untrusted_interactive_sealed_egress(
            model,
            interrupts.is_interactive_attached(),
            &tools,
            &session.db,
            &registry,
            session.id,
            config.generation(),
            crate::db::session_log::now_ms(),
        )
        .await;

    let mut prepared_request = model.prepare_completion_request(
        &agent.system,
        history,
        &prompt,
        &tools,
        &agent.params,
        endpoint_recovery.is_some(),
        sealed_egress.as_deref(),
    )?;
    // The immutable post-render request body for this dispatched-target attempt.
    // Written once, at dispatch, keyed `(call_id, ordinal)`; phase timestamps
    // and the terminal status land in dedicated columns via a status-advance,
    // never by rewriting this blob.
    let dispatch_payload = prepared_request.captured.clone();
    let attempt_meta = crate::db::session_log::InferenceAttemptMeta {
        provider: Some(model.provider_id()),
        model: Some(model.model_id_ref()),
        trust: Some(if model.is_trusted() {
            "trusted"
        } else {
            "untrusted"
        }),
    };
    let mut journal_attempt =
        prepare_inference_journal(&session, model, &dispatch_payload, call_id, ordinal).await?;
    // Pre-policy session table + target trust for protected-history journaling
    // (decision 10.2). Journaling scans the PRE-policy table, never the
    // trusted-empty effective table, and only journals for a trusted target.
    let session_redact_table = model.session_redact_table();
    let pending_write_failed = session
        .insert_inference_attempt(
            call_id,
            ordinal,
            &dispatch_payload,
            attempt_meta,
            goal_provenance,
            session_redact_table.as_ref(),
            model.is_trusted(),
        )
        .await
        .is_err();
    if pending_write_failed {
        if journal_attempt.is_none() {
            // Dual failure: the primary audit row could not be written AND no
            // durable journal is installed for this session, so NOTHING records
            // this inference. Fail closed — refuse the provider handoff rather
            // than dispatch an unaudited call. (When a journal IS present, its
            // `dispatching` commit already durably authorized this one handoff,
            // so a primary-row failure is the recoverable degraded path below.)
            anyhow::bail!(
                "inference audit unavailable: primary audit write failed and no durable journal \
                 is installed; provider handoff refused"
            );
        }
        tracing::warn!(
            "primary inference audit write failed; the durable journal holds the pending record"
        );
    }
    // Normal provider retry/recovery policy remains unchanged. Only the
    // journal-backed degraded path is limited to the single handoff that the
    // durable attempt authorizes.
    prepared_request.single_handoff = pending_write_failed;

    // Model-comparison tandem (shadow) dispatch (`model-comparison-
    // tandem-inference.md`). Fired HERE — right before the main call, after the
    // exact post-redaction history is assembled (incl. any live guidance-diff
    // injection above) — so each tandem model receives a byte-identical body to
    // the main model's, on the SAME `call_id`. A pure DB-only observer: never
    // executed, never enters history, never affects this turn's control flow.
    // `None` on the backup attempt so a fallback retry doesn't double-shadow.
    // Skipped for utility calls automatically — those never run through `turn`.
    if let Some(set) = tandem.filter(|s| s.is_enabled()) {
        // The tandem shadow has NO sensitive-turn barrier (its output is DB-only,
        // never dispatched or persisted as assistant prose), so it must NOT
        // advertise `report_leak`: a shadow `report_leak` call would carry the
        // plaintext `secret` into the recorded tandem outcome with nothing to
        // contain it. Strip it here so schema-advertisement stays coupled to the
        // barrier (AC3) — the shadow body differs only by the absent ingress
        // tool, which is host containment plumbing, not a task capability.
        let shadow_tools: Vec<ToolDefinition> = tools
            .iter()
            .filter(|t| t.name != crate::leak_report::REPORT_LEAK_TOOL)
            .cloned()
            .collect();
        let dispatch = crate::engine::schedule::TandemDispatch {
            parent_call_id: call_id.to_string(),
            agent: agent.name.clone(),
            system: agent.system.clone(),
            history: history.clone(),
            prompt: prompt.clone(),
            tools: shadow_tools,
            params: agent.params.clone(),
        };
        crate::engine::schedule::tandem::dispatch_turn(&session, set, dispatch);
    }

    // Buffered delivery sink (AC1/2/2b/2c). On an eligible route, wrap `tx` so
    // this turn's `AssistantTextDelta` / `ReasoningDelta` chunks are WITHHELD
    // from the live client stream until the sensitive-turn barrier classifies
    // the turn below; every other event still streams live. On an ineligible
    // route (trusted or tool-disabled) `tx` is used directly and streaming is
    // unchanged.
    let (delivery_event_tx, delivery_sink) = if report_leak_eligible {
        let (inner_tx, sink) =
            crate::engine::agent::sensitive_delivery::BufferedDeliverySink::spawn(
                tx.clone(),
                cancel.clone(),
            );
        (Some(inner_tx), Some(sink))
    } else {
        (None, None)
    };

    // Production display path: construct classifier at successful-attempt
    // dispatch inside complete_prepared. Config mirrors the turn's think /
    // translation / tokenizer settings so streamed deltas and the durable
    // snapshot measure the same user-visible text.
    let display_slot =
        Some(shared_display_slot.unwrap_or_else(|| new_display_attempt_slot(&session, &config)));

    let completion = model
        .complete_prepared_with_pre_drain(
            prepared_request,
            &tools,
            agent.params.clone(),
            &agent.name,
            Some(delivery_event_tx.as_ref().unwrap_or(tx)),
            &cancel,
            endpoint_recovery,
            None,
            false,
            display_slot.clone(),
        )
        .await;

    // Close the wrapped sender so the forwarder task finishes, then collect the
    // withheld deltas (`None` on an ineligible route). On the provider-error /
    // cancellation / drop path in the `Err` arm below, `withheld` is dropped
    // WITHOUT flushing (fail-closed Discarded — no pre-classification plaintext
    // ever reaches the client). On the success path it is flushed only when the
    // sensitive-turn barrier classifies the turn non-sensitive (Released) with
    // no overflow.
    drop(delivery_event_tx);
    let withheld = match delivery_sink {
        Some(sink) => Some(sink.finish().await),
        None => None,
    };

    let ((msg_id, choice, usage), _captured_request, mut timing) = match completion {
        Ok(out) => out,
        Err(e) => {
            // A standalone terminal failure owns its display error here. The
            // backup wrapper passes `false` and decides after it knows whether
            // a replacement will begin.
            let display_error_emitted = if emit_inference_error_ui {
                display_slot
                    .as_ref()
                    .expect("display slot is always installed")
                    .finish_as_error(
                        &agent.name,
                        crate::engine::response_performance::DisplayErrorKind::Failed,
                        "inference failed",
                        Some(tx),
                    )
                    .await
            } else {
                false
            };
            // Settle the dispatch-time record to its terminal status and
            // surface the failure (inline error + recorded event), unless this
            // was a clean cancel / drain unwind (those keep their dedicated
            // sentinels and are handled by the driver without a red error). The
            // body blob is immutable: settle only advances status + phase
            // columns for this attempt's `(call_id, ordinal)`.
            record_inference_outcome(
                InferenceOutcomeRecord {
                    session: session.clone(),
                    call_id,
                    ordinal,
                    agent_name: &agent.name,
                    wire_api: model.wire_api_label(),
                    routing_metadata: model.routing_metadata_json(None),
                    emit_inference_error_ui: emit_inference_error_ui && !display_error_emitted,
                    goal_provenance,
                    tx,
                },
                &e,
            )
            .await;
            let audit_settled = settle_inference_journal_error(&mut journal_attempt, &e).await;
            let e = e.context(format!("completion call for agent `{}`", agent.name));
            return Err(provider_error_remains_primary(e, audit_settled));
        }
    };

    // Settle the dispatch-time record to `completed`, filling the phase-timestamp
    // columns now known (`first_token_ms` / `completed_ms`) WITHOUT touching the
    // immutable body blob. Best-effort.
    if session
        .advance_inference_request(
            call_id,
            ordinal,
            crate::db::session_log::InferenceRequestStatus::Completed,
            crate::db::session_log::InferencePhaseTimings {
                first_token_ms: timing.first_token_ms.map(|ms| ms as i64),
                completed_ms: Some(timing.completed_ms as i64),
                failed_ms: None,
            },
        )
        .await
        .is_err()
    {
        tracing::warn!("primary inference audit terminal write failed");
    }
    if !settle_inference_journal_success(&mut journal_attempt).await {
        tracing::warn!("secondary inference audit reconciliation failed");
    }
    // Record the single `inference_request` timeline event for this call, now
    // that the provider reported usage (Part B). The export resolves the
    // `file` name deterministically from the event's seq + short_id + call_id
    // and emits the captured body (with phase timestamps + status) for it.
    let usage_json = usage.map(|u| {
        serde_json::json!({
            "input_tokens": u.input_tokens,
            "output_tokens": u.output_tokens,
            "cached_input_tokens": u.cached_input_tokens,
            "cache_creation_input_tokens": u.cache_creation_input_tokens,
        })
    });
    if let Err(e) = session
        .record_event_with_model_frame(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some(&agent.name),
            Some(&call_id.to_string()),
            crate::session::SessionEventModelFrame {
                provider_id: model.provider_id(),
                model_id: model.model_id_ref(),
                config: &config,
                session_table: session_redact_table.as_ref(),
            },
            &serde_json::json!({
                "usage": usage_json,
                "routing": model.routing_metadata_json(None),
                // The dispatched-target attempt index correlates this event to
                // its immutable `(call_id, ordinal)` inference-request row so
                // the export emits and names the right attempt file.
                "ordinal": ordinal,
            }),
        )
        .await
    {
        tracing::warn!(error = %e, "record inference_request event (completed) failed");
    }

    let _ = tx
        .send(TurnEvent::InferenceSucceeded {
            provider: model.provider_id().to_string(),
            model: model.model_id_ref().to_string(),
        })
        .await;

    // Assistant output text, extracted once: used both for the
    // calibration text basis below and the AssistantText emit further
    // down.
    let raw_text = extract_text(&choice);

    // Inline `<think>` handling (implementation note).
    // Reasoning is ALWAYS split off the raw text through the SAME shared
    // parser the TUI streams with — but this NEVER alters the current turn:
    // the continue-vs-end decision is driven by the raw choice's tool calls
    // (below), exactly as for a non-reasoning model. A leading `<think>` is
    // only split when it has a matching `</think>`; an unterminated one stays
    // as body under either toggle.
    //
    // Two independent rules apply post-turn:
    //
    //   Rule 1 — reasoning is NEVER replayed across turns. Whatever is
    //   classified as reasoning drove this turn but is absent from every later
    //   request's history; only body text + tool calls carry forward. It is
    //   preserved on the dedicated `reasoning` field for chip display only.
    //   Native channel reasoning (`reasoning_content`) is already dropped from
    //   the wire by `model::strip_reasoning`; inline `<think>` classified as
    //   thinking is dropped from stored history by `stored_assistant_choice`.
    //
    //   Rule 2 — the per-model/provider/global toggle (`inline_think`)
    //   CLASSIFIES a leading inline `<think>…</think>` block:
    //     ON (default): the block COUNTS AS THINKING — split off, shown as the
    //       "Thinking…" chip, and (per rule 1) dropped from later turns.
    //     OFF: the block COUNTS AS RESPONSE BODY — left inline in the body,
    //       shown as ordinary response text, carried forward like any other
    //       body text (rule 1 doesn't touch it; no chip).
    let inline_think = inline_think_enabled(&session, &config);
    let channel_reasoning = extract_reasoning(&choice);
    let (split_body, inline_reasoning) = crate::engine::think::split_think(&raw_text);
    // How the toggle CLASSIFIES a leading inline `<think>…</think>` block
    // (implementation note):
    //   ON  — it is THINKING: the body is the post-split answer and the
    //         block feeds the "Thinking…" chip (and is dropped from stored
    //         history by `stored_assistant_choice` so it never replays).
    //   OFF — it is RESPONSE BODY: the block stays inline in the displayed
    //         text and is carried forward like any other body text; no chip.
    // Either way an unterminated `<think>` is body (split_think leaves it).
    // `mut`: the reasoning-channel rescue (below, after `calls` is known) may
    // promote `reasoning` into `text` on a terminal turn whose answer landed in
    // the wrong channel (implementation note).
    let mut text = if inline_think {
        split_body
    } else {
        raw_text.clone()
    };
    // Native channel `reasoning_content` is always genuine reasoning, so it
    // always feeds the chip (it is already dropped from the wire by
    // `model::strip_reasoning`, never replayed — rule 1). Inline `<think>`
    // only feeds the chip when classified as thinking (toggle ON).
    let inline_chip = if inline_think {
        inline_reasoning.as_str()
    } else {
        ""
    };
    let mut reasoning = match (channel_reasoning.is_empty(), inline_chip.is_empty()) {
        (true, _) => inline_chip.to_string(),
        (false, true) => channel_reasoning,
        (false, false) => format!("{channel_reasoning}\n{inline_chip}"),
    };
    if let Some(u) = usage {
        if let Err(e) = record_usage_blocking(session.clone(), call_id, u).await {
            tracing::warn!(error = %e, "session.record_usage failed");
        }
        // Feed the round into tokenizer calibration only after the cheap
        // discard guards pass. Building the basis serializes the whole turn
        // history and is intentionally skipped when the sample cannot be used.
        if session.should_note_calibration_sample(u).await {
            let mut basis = String::new();
            for m in history.iter() {
                if let Ok(s) = serde_json::to_string(m) {
                    basis.push_str(&s);
                }
            }
            if let Ok(s) = serde_json::to_string(&prompt) {
                basis.push_str(&s);
            }
            basis.push_str(&text);
            session.note_calibration_sample(&basis, u).await;
        }

        let _ = tx
            .send(TurnEvent::Usage {
                agent: agent.name.clone(),
                usage: u,
            })
            .await;
    }

    // Persist the assistant turn per the toggle's CLASSIFICATION of an inline
    // `<think>` block (`stored_assistant_choice`): ON it is thinking, so the
    // block is STRIPPED from stored history (rule 1 — reasoning never replays);
    // OFF it is response body, so the raw choice is stored verbatim and carries
    // forward. Stripping happens ONCE here, at store time — never as a
    // re-mutation of older history turns, so the cached system+history prefix
    // stays byte-stable across turns (prompt-cache safety). Channel `Reasoning`
    // blocks ride along either way and are dropped on the wire by
    // `model::strip_reasoning`.
    //
    // When the toggle is ON, a turn that strips to nothing (reasoning only, no
    // body, no tool call) collapses to `None` (`strip_think_from_choice`): we
    // drop the assistant turn rather than persist a blank `[{"text":""}]`
    // message that would poison every later request (defect B). The round's
    // `prompt` (the user/tool-result message) is always pushed; only the empty
    // assistant turn is dropped.
    // Provider sensitive-turn barrier (AC2/AC3/AC10). The provider adapters have
    // already aggregated every streamed tool-call delta into this one buffered
    // per-turn vector before any generic dispatch runs, so this is the single
    // cross-decoder chokepoint. An ingress-only `report_leak` call is intercepted
    // here — BEFORE it can reach generic tool dispatch, history persistence,
    // stream-to-parent delivery, audit, or export — and routed through the
    // fail-closed host ingress `decode_and_contain_report_leak`; the reported
    // secret is installed into the LIVE redaction table BEFORE the turn is acked,
    // and every other buffered item for the turn is then discarded. A turn with no
    // sensitive-ingress call passes through byte-identically to before.
    let buffered_calls: Vec<ToolCall> = collect_tool_calls(&choice);
    // Decode/contain ONLY on a route that advertised `report_leak`
    // (`report_leak_eligible`) — the SAME funnel that gates the schema append and
    // the withhold sink. A trusted / tool-disabled / unsupported route never
    // advertised the schema, so a hallucinated `report_leak`-named call there is
    // NOT decoded or contained; it falls through to ordinary unknown-tool
    // handling (its plaintext arg is never parsed or durably contained).
    let sensitive_turn_active = crate::engine::agent::sensitive_turn::sensitive_turn_engages(
        report_leak_eligible,
        &buffered_calls,
    );

    // Buffered-delivery verdict (AC1/2/2b/2c). The turn is now classified. The
    // withheld buffer is flushed to the live client ONLY on a clean Released
    // turn: non-sensitive, not overflowed, and not cancelled (flagged by the
    // sink's cancellation arm OR observed live via `cancel.is_cancelled()` for
    // the ordering where cancellation fired after the forwarder closed). Every
    // other outcome — a sensitive/contained turn, overflow, cancellation, or the
    // provider-error path handled in the `Err` arm above — DROPS the buffer
    // without flushing, so no pre-classification plaintext reaches the client.
    // `withheld` is `None` on an ineligible route, where deltas streamed live.
    let withheld_overflow = withheld.as_ref().is_some_and(|w| w.overflowed());
    if let Some(withheld) = withheld {
        let should_flush = crate::engine::agent::sensitive_delivery::withheld_should_flush(
            sensitive_turn_active,
            &withheld,
            cancel.is_cancelled(),
        );
        if should_flush {
            withheld.flush_to(tx).await;
        }
        // else: dropped here without flushing (fail-closed).
    }
    // A turn's output is CONTAINED (collapsed — nothing dispatched, emitted, or
    // persisted) when the sensitive-turn barrier fired OR the withhold buffer
    // overflowed. Overflow reuses the same fail-closed collapse as a sensitive
    // turn: content-free status, no plaintext anywhere.
    let turn_output_contained = sensitive_turn_active || withheld_overflow;

    let mut calls: Vec<ToolCall> = if sensitive_turn_active {
        // Host-derived provenance from the active route; the model never supplies it.
        let provenance = crate::db::protected_leak_records::LeakProvenance {
            provider_id: Some(model.provider_id().to_owned()),
            model_id: Some(model.model_id_ref().to_owned()),
            generation: None,
            connector_id: None,
        };
        let key_resolver = session.redaction_key_resolver().clone();
        let host = crate::engine::agent::sensitive_turn::LiveSensitiveContainmentHost {
            db: &session.db,
            key_resolver: key_resolver.as_ref(),
            interrupts: interrupts.as_ref(),
            session: session.as_ref(),
            provenance,
            session_id: session.id.to_string(),
            now_ms: chrono::Utc::now().timestamp_millis(),
        };
        let sensitive_outcome =
            crate::engine::agent::sensitive_turn::run_sensitive_turn_barrier(&host, buffered_calls)
                .await;
        for result in &sensitive_outcome.sensitive_results {
            // Content-free: `contained` / `rate_limited` / `failed`. Never plaintext.
            tracing::info!(
                target: "engine",
                agent = %agent.name,
                state = ?sensitive_outcome.state,
                outcome = %result.model_output,
                "report_leak containment barrier classified the turn"
            );
        }
        // Collapse: no generic (ordinary) call survives a sensitive turn, so no
        // buffered non-sensitive item reaches parent/UI/history/tool/audit/export.
        sensitive_outcome.generic_calls
    } else if withheld_overflow {
        // Overflow fail-closed: discard the whole turn's output, dispatch nothing.
        Vec::new()
    } else {
        buffered_calls
    };

    if turn_output_contained {
        // Fail closed: drop this turn's surviving assistant text and reasoning so
        // they can never be persisted to durable history (which scrubs only with
        // the stale pre-turn `model.session_redact_table()` snapshot, not the live
        // post-install table) nor emitted to the client raw. On a Contained turn
        // the reported secret IS installed into the live redaction table (so later
        // turns are scrubbed) but this turn's own prose is sacrificed rather than
        // re-scrubbed; on a Discarded turn nothing was installed, so it MUST be
        // dropped. On an overflow turn the withheld deltas were already dropped
        // above and nothing else is emitted. Blanking both makes the final
        // AssistantMessage persist + the AssistantText client emit below skip
        // entirely (their guard is
        // `!text.trim().is_empty() || !reasoning.trim().is_empty()`).
        //
        // The LIVE streaming `AssistantTextDelta` / `ReasoningDelta` for this turn
        // were WITHHELD by the buffered delivery sink (AC1) — they never reached
        // the client during completion — and are dropped (not flushed) on this
        // contained/overflow path, so no pre-classification plaintext escapes on
        // any channel.
        text.clear();
        reasoning.clear();
    }

    // Harmony / ChatML special-token sanitizer
    // (implementation note): some local-template
    // backends (observed on gemma-4-26b-a4b via lm-studio) bleed a raw special
    // token (e.g. a bare `<|channel>`) into `text` at the channel boundary while
    // the real content went to a `tool_call`. Strip an UNAMBIGUOUS leading-marker
    // bleed artifact; prose/code citing the token is left untouched (conservative
    // scope — strong-API models never hit it). Runs BEFORE the reasoning-channel
    // rescue so a `text` that sanitizes to `""` feeds the rescue's emptiness check
    // naturally. The pre-strip content is recorded as `data.original_text` on the
    // assistant_message event below (GOALS §14 wire-vs-user split); the stripped
    // form is the SINGLE version both the user sees and the wire history carries,
    // so the model isn't re-prompted with its own broken output.
    let harmony_strip = sanitize_harmony_tokens(&text);
    let harmony_original = harmony_strip.as_ref().map(|_| text.clone());
    if let Some((stripped, stage)) = &harmony_strip {
        tracing::debug!(
            target: "engine",
            agent = %agent.name,
            stage = stage.stage(),
            "harmony sanitizer: stripped leading special-token bleed from text"
        );
        text = stripped.clone();
    }

    // Reasoning-channel rescue (implementation note):
    // a weak model whose chat template routed its FINAL answer onto the
    // reasoning channel leaves `text` empty while the real answer sits in
    // `reasoning` — the user (and, after `model::strip_reasoning` drops the
    // reasoning-only turn, the model's own later history) would see nothing.
    // Fire ONLY on a terminal, user-facing turn (`is_root && calls.is_empty()`,
    // the same boundary the user-facing answer uses below): empty `text`,
    // non-empty `reasoning`, no tool call. We then promote the verbatim
    // reasoning into `text` (prefixed with a one-line italic chip) so it is the
    // SINGLE version both the user sees and the model reads back — no dual copy
    // (GOALS §14: the reasoning was already invisible to the user, so this
    // surfaces, never rewrites). A tool-call turn (active, not answering) and a
    // whitespace-only reasoning never fire. Unconditional — no config knob.
    let reasoning_rescue = reasoning_channel_rescue(is_root, calls.is_empty(), &text, &reasoning);
    if reasoning_rescue {
        tracing::debug!(
            target: "engine",
            agent = %agent.name,
            reasoning_len = reasoning.len(),
            "reasoning-channel rescue: promoting reasoning to user-visible text"
        );
        text = promote_reasoning(&reasoning);
    }

    // Wire-history form. Normally derived from the provider's `choice` (an
    // inline-`<think>` body is stripped when the toggle classifies it as
    // thinking). On a reasoning-channel rescue we instead store the promoted
    // text verbatim as a single `Text` part: the original `choice` carries the
    // answer only on a `Reasoning` block, which `model::strip_reasoning` drops
    // from the wire — so without this the model would never see its own answer
    // on the next turn. The promoted form is identical to the user-visible
    // `text`, keeping the wire and user transcripts in lockstep.
    let stored_choice = if reasoning_rescue {
        Some(vec![crate::engine::message::AssistantContent::text(
            text.clone(),
        )])
    } else if harmony_strip.is_some() {
        // A leading Harmony special-token bleed was stripped from `text`: rebuild
        // the wire choice with the sanitized text in place of the bled `Text`
        // part (preserving any tool call the same turn carried), so the model
        // reads back the stripped form, not its own broken output. An
        // inline-`<think>` body is irrelevant here — the bleed shape is a bare
        // marker, never a `<think>` block.
        crate::engine::message::replace_text_in_choice(&choice, &text)
    } else {
        stored_assistant_choice(inline_think, &choice)
    };
    // Contained-turn collapse (fail closed): drop the ENTIRE assistant turn from
    // wire history. On a sensitive turn its buffered tool calls (the `report_leak`
    // ingress call and any other ordinary call) were withheld from generic
    // dispatch; on an overflow turn nothing survives. Its text/reasoning were
    // blanked above, so persisting any part of the raw choice would either replay
    // the plaintext `secret` argument of the report_leak call or leave a
    // `tool_use` without a matching `tool_result`.
    let stored_choice = if turn_output_contained {
        None
    } else {
        stored_choice
    };
    history.push(prompt);
    if let Some(stored_choice) = stored_choice {
        history.push(Message::Assistant {
            id: msg_id.clone(),
            content: stored_choice,
        });
    }

    // Text-embedded tool-call recovery (implementation note):
    // a weak model that emitted its call as TEXT (a fenced block / bare JSON in
    // the assistant message) leaves the structured `tool_calls` field EMPTY —
    // recovery only ever fires in that case (a real structured call always wins
    // and the text is left alone). The structural gate + format normalization +
    // fuzzy name-repair + existence check run here; the resolved decision drives
    // whether we synthesize a real call (dispatched below through the SAME
    // validate-then-repair + permission + execution path), nudge the model
    // (`available` unknown tool), feed back an `unknown tool` result (`strict`),
    // or do nothing. `recovered_marker` keys the synthesized call's id to its
    // §14 recovery marker (text block as `original_input`, structured call as
    // wire) so the dispatch loop records it as a [`Recovery::TextEmbedded`].
    let mut recovered_markers: std::collections::HashMap<String, Recovery> =
        std::collections::HashMap::new();
    // A pending `available`-mode nudge (model-side correction) to inject into
    // history after the AssistantText is emitted, so the block surfaces to the
    // user before the system nudge. `Some((notice, nudge))`.
    let mut available_nudge: Option<(String, String)> = None;
    if !turn_output_contained && should_attempt_text_recovery(calls.is_empty(), reasoning_rescue) {
        let mode = text_embedded_recovery_mode(&session, &config);
        match decide_text_recovery(&agent.tools, &text, mode) {
            TextRecoveryDecision::None => {}
            TextRecoveryDecision::Recovered(rec) => {
                // Surface a recovery notice so the user sees a text-form call was
                // recovered, uniformly across structural (`task`) and ordinary
                // tools — the §14 chip on the tool_call row covers ordinary
                // tools, but a structural tool returns early before any row.
                let dropped = matches!(
                    &rec.marker,
                    Recovery::TextEmbedded {
                        dropped_trailing: true,
                        ..
                    }
                );
                let mut notice = format!(
                    "Recovered a tool call `{}` the agent emitted as text.",
                    rec.call.function.name
                );
                if dropped {
                    notice.push_str(" Trailing batched entries were dropped.");
                }
                let _ = tx.send(TurnEvent::Notice { text: notice }).await;
                append_tool_call_to_last_assistant(history, &rec.call);
                recovered_markers.insert(rec.call.id.to_string(), rec.marker);
                calls.push(rec.call);
            }
            TextRecoveryDecision::UnknownStrict { call, unknown } => {
                // Inject the synthesized (unknown-named) call so the standard
                // unknown-tool failure the dispatch loop produces pairs with a
                // tool_use on the wire. No marker — the row records the natural
                // `not_in_advertised_set` rejection + hard-fail tool_result.
                append_tool_call_to_last_assistant(history, &call);
                tracing::info!(
                    target: "repair",
                    tool = %unknown,
                    "text_embedded_recovery strict: unknown tool fed back to model"
                );
                calls.push(call);
            }
            TextRecoveryDecision::UnknownAvailable {
                unknown,
                available_tools,
            } => {
                // `available` mode + unresolved name: do NOT execute. Surface a
                // yellow warning chip to the user and stage a model-side nudge so
                // it self-corrects on the next turn instead of looping.
                let notice = format!(
                    "Looks like the agent tried and failed a tool call to `{unknown}` (not an available tool)."
                );
                let nudge = unknown_tool_nudge(&unknown, &available_tools);
                available_nudge = Some((notice, nudge));
                tracing::info!(
                    target: "repair",
                    tool = %unknown,
                    "text_embedded_recovery available: unknown tool surfaced + nudged"
                );
            }
        }
    }

    // Even with streaming, emit a final AssistantText so the TUI knows
    // to freeze the live-streaming entry into a static history row.
    // Non-streaming paths land here directly. `text` is the classified body
    // (post-split when the toggle is ON, raw when OFF), `reasoning` the chip
    // text (channel + inline-when-ON), both computed above.
    //
    // We finalize whenever there is body text OR reasoning: a reasoning-only
    // turn (reasoning + a tool call, no answer) has empty `text` but, when the
    // toggle is ON, must still persist its reasoning so the thinking chip
    // survives resume and appears in exports — the TUI renders just the chip
    // (+ the tool call), never an empty bubble. When the toggle is OFF an
    // inline block is body (so it shows as text, not a chip); a body-less,
    // reasoning-less turn finalizes nothing.
    // Either way this is presentation only — the turn's continue-vs-end
    // decision is the raw `calls.is_empty()` check below, never this branch.
    if !text.trim().is_empty() || !reasoning.trim().is_empty() {
        // Outbound translation (implementation note): when this
        // is the foreground primary's *final* user-facing answer (root frame,
        // no tool calls this turn), translate the COMPLETE assembled text from
        // the model's language back into the user's. The translated form is
        // shown to the user only — the model-language `text` already went into
        // `history` (the wire/transcript split is preserved: the model sees
        // its own output, the user reads the translation) and the timeline
        // `AssistantMessage` event below records the original. When
        // translation is inactive (languages unset/equal, or the utility
        // model is unset/erroring) the text is emitted unchanged — identical
        // to the pre-feature behavior. No streaming translation: the
        // translated answer lands once, here, after the response completes.
        let shown = if is_root && calls.is_empty() && !text.trim().is_empty() {
            translate_final_response(
                &text,
                &config,
                redact.clone(),
                Some(agent.model.shutdown_gate()),
            )
            .await
        } else {
            text.clone()
        };
        // Timeline event (Part B). Tagged with the same `call_id` as the
        // request that produced it so the export can group a turn. Records the
        // model's *original* (stripped) text plus its reasoning on a dedicated
        // field — the reasoning survives `/prune` / `/compact` and repopulates
        // the thinking chip on resume (rehydrate.rs), but never re-enters
        // model context. The translated user-facing form is never recorded.
        // Recorded BEFORE the `AssistantText` UI event so the assigned `seq`
        // (the message's stable id) can ride along (`pinned-messages`).
        // The event `data` is free-form JSON (`session.record_event`), so the
        // reasoning-channel rescue records its audit as a `data.recovery =
        // { kind, stage }` sub-object — NOT the tool-call `recovery_kind`/
        // `recovery_stage` columns. Those live on the `tool_call_events` table
        // and are driven by the tool-call-coupled `repair::Recovery` enum;
        // reusing them for an `assistant_message` event would require a fake
        // tool-call row or a new enum variant (schema gymnastics the spec lets
        // us avoid). The `{ kind, stage }` shape still follows the GOALS §14
        // wire-vs-user recovery naming convention.
        let mut event_data = serde_json::json!({ "text": text, "reasoning": reasoning });
        // Persist `presentation_text` when it differs from `text` (translation
        // success). Silent fallback (identical) persists only `text`. Legacy
        // rows without `presentation_text` display `text`.
        if shown != text {
            event_data["presentation_text"] = serde_json::json!(shown);
        }
        // Finish the attempt-dispatch classifier before the timeline write so
        // the durable `response_performance` snapshot is recorded with the row.
        let (presentation_text, response_performance, display_complete) =
            if let Some(mut classifier) = timing.open_display.take() {
                let translated = if shown != text {
                    Some(shown.clone())
                } else {
                    None
                };
                match classifier.finish(&text, &reasoning, translated) {
                    Some(complete) => {
                        let assistant = complete.assistant;
                        let perf = assistant.response_performance;
                        let presentation = assistant.presentation_text.clone();
                        (presentation, perf, Some((complete.attempt_id, assistant)))
                    }
                    None => (
                        if shown != text {
                            Some(shown.clone())
                        } else {
                            None
                        },
                        None,
                        None,
                    ),
                }
            } else {
                (
                    if shown != text {
                        Some(shown.clone())
                    } else {
                        None
                    },
                    None,
                    None,
                )
            };
        if let Some(perf) = &response_performance {
            event_data["response_performance"] = serde_json::json!({
                "ttft_ms": perf.ttft_ms,
                "generation_ms": perf.generation_ms,
                "displayed_tokens": perf.displayed_tokens,
                "encoding": perf.encoding.as_str(),
            });
        }
        if reasoning_rescue {
            event_data["recovery"] = serde_json::json!({
                "kind": "reasoning_channel_rescue",
                "stage": "promoted",
            });
        } else if let Some((_, stage)) = &harmony_strip {
            // Harmony special-token bleed stripped: record the recovery audit and
            // preserve the pre-strip content as `data.original_text` (GOALS §14
            // wire-vs-user split, mirroring `tool_call`'s `original_input`). The
            // `text`/wire form both carry the stripped value; only this audit
            // field retains the raw bleed.
            event_data["recovery"] = serde_json::json!({
                "kind": "harmony_token_strip",
                "stage": stage.stage(),
            });
            if let Some(original) = &harmony_original {
                event_data["original_text"] = serde_json::json!(original);
            }
        }
        let assistant_session_table = model.session_redact_table();
        let seq = match session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::AssistantMessage,
                Some(&agent.name),
                Some(&call_id.to_string()),
                crate::session::SessionEventModelFrame {
                    provider_id: model.provider_id(),
                    model_id: model.model_id_ref(),
                    config: &config,
                    session_table: assistant_session_table.as_ref(),
                },
                &event_data,
            )
            .await
        {
            Ok(seq) => Some(seq),
            Err(e) => {
                tracing::warn!(error = %e, "record assistant_message event failed");
                None
            }
        };
        // Live Complete retains its computed snapshot even when the timeline
        // write failed (foundation: live event survives write failure).
        if let Some((attempt_id, mut assistant)) = display_complete {
            assistant.seq = seq;
            // Prefer the finished snapshot; write failure must not drop it.
            if assistant.response_performance.is_none() {
                assistant.response_performance = response_performance;
            }
            let _ = tx
                .send(TurnEvent::AssistantDisplayComplete {
                    agent: agent.name.clone(),
                    attempt_id,
                    assistant: assistant.clone(),
                })
                .await;
            let _ = tx
                .send(TurnEvent::AssistantText {
                    agent: agent.name.clone(),
                    text: assistant.text,
                    presentation_text: assistant.presentation_text,
                    reasoning: assistant.reasoning,
                    seq: assistant.seq,
                    response_performance: assistant.response_performance,
                })
                .await;
        } else {
            let _ = tx
                .send(TurnEvent::AssistantText {
                    agent: agent.name.clone(),
                    text: shown.clone(),
                    presentation_text,
                    reasoning: reasoning.clone(),
                    seq,
                    response_performance,
                })
                .await;
        }
    }

    // `available`-mode unrecovered text call (implementation note):
    // the block was already surfaced to the user as the AssistantText above; now
    // emit the yellow warning chip (a `Notice`) and inject the model-side
    // correction nudge as a system message so the next turn steers the model to
    // re-emit a real call instead of looping. The nudge goes through the §7
    // redaction chokepoint like any other outbound content. This path does NOT
    // execute anything — it returns `Done` (the turn produced no dispatchable
    // call), and the staged system message rides into the next request.
    if let Some((notice, nudge)) = available_nudge {
        let _ = tx.send(TurnEvent::Notice { text: notice }).await;
        history.push(Message::System { content: nudge });
    }

    if calls.is_empty() {
        return Ok(TurnOutcome::Done);
    }

    // Tool dispatch.
    let ctx = ToolCtx {
        agent_id: agent.name.clone(),
        agent_instance_id: crate::engine::agent::current_agent_instance_id(),
        lock_identity: agent.lock_identity.clone(),
        write_scope: agent.write_scope.clone(),
        current_tool_call_id: None,
        llm_mode: agent.llm_mode,
        locks,
        session: session.clone(),
        cwd: cwd.clone(),
        redact: redact.clone(),
        env_overlay: agent.env_overlay.clone(),
        interrupts,
        cancel,
        shutdown_gate: agent.model.shutdown_gate(),
        approver,
        image_generation_dispatch: None,
        deferred_log,
        root_agent_frame: is_root,
        skill_write_origin,
        review_cage,
        context_usage: Some(context_usage),
        available_tools: Arc::new(
            active_tools
                .names()
                .into_iter()
                .map(str::to_string)
                .collect(),
        ),
        mcp_builtin_registry: active_tools.mcp_builtin_registry(),
        has_tree: agent.tools.get("code").is_some(),
        has_bash: agent.tools.get("bash").is_some(),
        // The blocked-`read` waiting indicator routes its
        // `WaitingForLock` start/clear pair back through this same turn
        // event stream (`read-wait-and-lock-expiry.md`).
        events: Some(tx.clone()),
        lsp,
        resource_scheduler,
        config: config.clone(),
    };

    // Per-call dispatch repair pipeline (fixed order, idempotent — a reorder
    // is a contract break; see `composed-repair-pipeline-idempotence.md`):
    //   1. name normalize/rebind (`repair::repair_tool_name`)
    //   2. §12 args input-repair (`repair::repair`, schema by the RESOLVED name)
    //   3. path-normalize (`repair::normalize_paths`)
    // Order is load-bearing: (2)/(3) need the name (1) resolved to look up the
    // schema. Re-running on the already-repaired call is a no-op (`Clean`).
    //
    // Whether §12 corrections are surfaced to the model as `<repair_note>`
    // lines on the wire tool_result (implementation note).
    // Resolved once per turn (model > provider > global, default off); when
    // off, behavior is exactly as before (silent canonical rewrite + user
    // chip). The user-facing transcript is never altered by this — only the
    // wire form the model reads.
    let hint_corrections = hint_tool_call_corrections_enabled(&session, &config);
    for tc in &calls {
        // Tool-NAME repair (implementation note), run BEFORE
        // the registry lookup and the args validate-then-repair (§12). Two
        // layers: (a) deterministically normalize a junk name and rebind it
        // to a registered tool on an exact (never fuzzy) match, so a weak
        // model emitting `read\n`/`<read>`/`functions.read`/`Read` dispatches
        // without a wasted round-trip; (b) charset-sanitize a still-unknown
        // name to `^[a-zA-Z0-9_-]{1,64}$` so the failed `tool_use` left in
        // history can't 400 the provider on replay. The structural tools
        // below (`task`/`schedule`/`spawn`/`done`) are
        // registered in the toolbox, so a rebind resolves them here and they
        // route correctly. `resolved_name` is the wire/model form; the
        // original (malformed) name rides `name_recovery` for the §14
        // wire-vs-user split. A clean exact match is a zero-cost passthrough
        // (`Recovery::Clean`, byte-identical to today).
        let known: Vec<&str> = active_tools.names();
        let name_repair = repair::repair_tool_name(&tc.function.name, &known);
        let resolved_name = name_repair.name.as_str();
        let name_recovery = name_repair.recovery;

        match phase_10_dispatch_one_call(agent, &session, &config, tx, tc, resolved_name).await? {
            ControlFlow::Break(outcome) => {
                rewrite_structural_call_name_if_repaired(
                    history,
                    tc,
                    resolved_name,
                    &name_recovery,
                );
                return Ok(outcome);
            }
            ControlFlow::Continue(()) => {}
        }

        let text_recovery_marker = recovered_markers.remove(tc.id.as_str());
        let config_snapshot = ctx.config.snapshot();
        let env = super::tool_dispatch::DispatchEnv {
            agent,
            session: &session,
            model,
            active_tools: &active_tools,
            ctx: &ctx,
            tx,
            hint_corrections,
            loop_guard_threshold,
            cwd: &cwd,
            hooks: config_snapshot.hooks(),
        };
        super::tool_dispatch::execute_ordinary_call(
            &env,
            history,
            tc,
            resolved_name,
            name_recovery,
            text_recovery_marker,
        )
        .await?;
    }

    Ok(TurnOutcome::Continue)
}

#[cfg(test)]
mod inference_audit_tests {
    use super::provider_error_remains_primary;

    #[test]
    fn inference_provider_error_remains_primary() {
        let provider = anyhow::anyhow!("provider-sentinel");
        let returned = provider_error_remains_primary(provider, false);
        assert_eq!(returned.to_string(), "provider-sentinel");
        assert!(!returned.to_string().contains("audit"));
    }
}

async fn inject_turn_start_system_messages(
    session: &Session,
    active_tools: &ToolBox,
    is_root: bool,
    context_usage: crate::engine::tool::ContextUsageSnapshot,
    history: &mut Vec<Message>,
) {
    let active_tool_names = active_tools.names();
    let sandbox_escalate_present = active_tool_names.contains(&"escalate");
    if let Some(notice) = session.sandbox_escalation_turn_notice(sandbox_escalate_present) {
        history.push(Message::System { content: notice });
    }
    if let Some(nudge) =
        session.unnamed_session_title_nudge(active_tool_names.contains(&"mcp"), is_root)
        && !history
            .iter()
            .any(|message| matches!(message, Message::System { content } if content == &nudge))
    {
        history.push(Message::System { content: nudge });
    }
    // Durable one-shot title-recovery nudge (issue #23), distinct from the
    // slot-8/16 unnamed-session nudge above. Armed by a failed automatic-title
    // pass; claimed atomically here so exactly one eligible root turn injects it
    // (claim-before-send prevents a duplicate across turns). Only a root frame
    // carrying `mcp` (Monty present) claims — a subagent/no-Monty frame never
    // consumes the latch.
    if let Some(nudge) = session
        .title_recovery_nudge(active_tool_names.contains(&"mcp"), is_root)
        .await
        && !history
            .iter()
            .any(|message| matches!(message, Message::System { content } if content == &nudge))
    {
        history.push(Message::System { content: nudge });
    }
    if let Some(nudge) = session.compact_self_nudge(
        context_usage.ctx_pct,
        context_usage.compact_nudge_pct,
        context_usage.auto_compact_pct,
        active_tool_names.contains(&"mcp"),
        is_root,
    ) && !history
        .iter()
        .any(|message| matches!(message, Message::System { content } if content == &nudge))
    {
        history.push(Message::System { content: nudge });
    }
    if active_tool_names.contains(&"mcp")
        && let Some(nudge) =
            crate::tools::mcp_tool::turn_start_advert_message(active_tools, session).await
        && !history
            .iter()
            .any(|message| matches!(message, Message::System { content } if content == &nudge))
    {
        history.push(Message::System { content: nudge });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ProviderEntry, ProvidersConfig};
    use rig::message::{ToolFunction, UserContent};

    fn test_model() -> Arc<Model> {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            ProviderEntry {
                url: "http://127.0.0.1:9/v1".to_string(),
                ..ProviderEntry::default()
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

    fn test_agent() -> Agent {
        Agent {
            name: "Build".to_string(),
            system: "system".to_string(),
            role_prompt: "system".to_string(),
            tools: ToolBox::new(),
            model: test_model(),
            params: ModelParams::default(),
            scan_tool_results: true,
            llm_mode: crate::config::extended::LlmMode::Normal,
            lock_identity: "Build".to_string(),
            write_scope: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            assistant_identity_prefix: None,
        }
    }

    fn test_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        Arc::new(
            Session::create_for_test(
                db,
                root.to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        )
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

    #[tokio::test]
    async fn nudge_is_injected_as_system_message() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        for turn in 1..=8 {
            let _ = session.note_user_content(&format!("turn {turn}"));
        }
        let toolbox = ToolBox::new().with(Arc::new(crate::tools::mcp_tool::McpTool));
        let mut history = Vec::new();

        inject_turn_start_system_messages(
            &session,
            &toolbox,
            true,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            &mut history,
        )
        .await;

        let nudges: Vec<_> = history
            .iter()
            .filter_map(|message| match message {
                Message::System { content } if content.contains("rename_session") => Some(content),
                _ => None,
            })
            .collect();
        assert_eq!(nudges.len(), 1);
        assert!(nudges[0].contains("after 8 user turns"));

        inject_turn_start_system_messages(
            &session,
            &toolbox,
            true,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            &mut history,
        )
        .await;
        let nudge_count = history
            .iter()
            .filter(|message| {
                matches!(message, Message::System { content } if content.contains("rename_session"))
            })
            .count();
        assert_eq!(nudge_count, 1, "same-slot nudge is one-shot");
    }

    #[tokio::test]
    async fn nudge_does_not_fire_for_subagent_frames() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        for turn in 1..=8 {
            let _ = session.note_user_content(&format!("turn {turn}"));
        }
        let toolbox = ToolBox::new().with(Arc::new(crate::tools::mcp_tool::McpTool));
        let mut history = Vec::new();

        inject_turn_start_system_messages(
            &session,
            &toolbox,
            false,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            &mut history,
        )
        .await;

        assert!(
            history.iter().all(
                |message| !matches!(message, Message::System { content } if content.contains("rename_session"))
            ),
            "{history:?}"
        );
    }

    #[tokio::test]
    async fn compact_nudge_injected_as_system_message() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        for turn in 1..=8 {
            let _ = session.note_user_content(&format!("turn {turn}"));
        }
        let toolbox = ToolBox::new().with(Arc::new(crate::tools::mcp_tool::McpTool));
        let context_usage = crate::engine::tool::ContextUsageSnapshot {
            ctx_pct: Some(62.0),
            used_tokens: Some(62_000),
            total_tokens: Some(100_000),
            compact_nudge_pct: 60,
            auto_compact_pct: 80,
        };
        let mut history = Vec::new();

        inject_turn_start_system_messages(&session, &toolbox, true, context_usage, &mut history)
            .await;

        let compact_nudges: Vec<_> = history
            .iter()
            .filter_map(|message| match message {
                Message::System { content } if content.contains("request_compact") => Some(content),
                _ => None,
            })
            .collect();
        assert_eq!(compact_nudges.len(), 1, "{history:?}");
        assert!(compact_nudges[0].contains("62%"));
        assert!(compact_nudges[0].contains("80%"));
        assert!(
            history.iter().any(
                |message| matches!(message, Message::System { content } if content.contains("rename_session"))
            ),
            "title nudge should coexist when simultaneously eligible"
        );

        inject_turn_start_system_messages(&session, &toolbox, true, context_usage, &mut history)
            .await;
        let compact_nudge_count = history
            .iter()
            .filter(|message| {
                matches!(message, Message::System { content } if content.contains("request_compact"))
            })
            .count();
        assert_eq!(compact_nudge_count, 1, "same nudge should not duplicate");

        let tmp = tempfile::tempdir().unwrap();
        let inactive = test_session(tmp.path());
        let mut inactive_history = Vec::new();
        inject_turn_start_system_messages(
            &inactive,
            &toolbox,
            true,
            crate::engine::tool::ContextUsageSnapshot {
                ctx_pct: Some(59.0),
                ..context_usage
            },
            &mut inactive_history,
        )
        .await;
        assert!(
            inactive_history.iter().all(
                |message| !matches!(message, Message::System { content } if content.contains("request_compact"))
            ),
            "{inactive_history:?}"
        );
    }

    #[tokio::test]
    async fn nudge_is_suppressed_without_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        for turn in 1..=8 {
            let _ = session.note_user_content(&format!("turn {turn}"));
        }
        let toolbox = ToolBox::new();
        let mut history = Vec::new();

        inject_turn_start_system_messages(
            &session,
            &toolbox,
            true,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            &mut history,
        )
        .await;

        assert!(
            history.iter().all(
                |message| !matches!(message, Message::System { content } if content.contains("rename_session"))
            ),
            "{history:?}"
        );
        let toolbox = ToolBox::new().with(Arc::new(crate::tools::mcp_tool::McpTool));
        inject_turn_start_system_messages(
            &session,
            &toolbox,
            true,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            &mut history,
        )
        .await;
        assert!(
            history.iter().all(
                |message| !matches!(message, Message::System { content } if content.contains("rename_session"))
            ),
            "suppressed unactionable nudge must not carry into a later turn"
        );
    }

    #[tokio::test]
    async fn discoverable_family_advert_is_not_injected_at_turn_start() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        let toolbox = ToolBox::new()
            .with(Arc::new(crate::tools::mcp_tool::McpTool))
            .with_discoverable_mcp(Arc::new(crate::tools::intel::CodeTool));
        let mut history = Vec::new();

        inject_turn_start_system_messages(
            &session,
            &toolbox,
            true,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            &mut history,
        )
        .await;

        let adverts: Vec<_> = history
            .iter()
            .filter_map(|message| match message {
                Message::System { content }
                    if content.contains("Available built-in cockpit functions") =>
                {
                    Some(content)
                }
                _ => None,
            })
            .collect();
        assert!(adverts.is_empty(), "{history:?}");
    }

    #[tokio::test]
    async fn no_advert_nudge_when_catalog_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        let toolbox = ToolBox::new().with(Arc::new(crate::tools::mcp_tool::McpTool));
        let mut history = Vec::new();

        inject_turn_start_system_messages(
            &session,
            &toolbox,
            true,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            &mut history,
        )
        .await;

        assert!(
            history.iter().all(
                |message| !matches!(message, Message::System { content } if content.contains("Available built-in cockpit functions"))
            ),
            "{history:?}"
        );
    }

    #[tokio::test]
    async fn phase_10_structural_return_breaks() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = test_agent();
        let session = test_session(tmp.path());
        let (tx, _rx) = mpsc::channel(1);
        let call = tool_call(
            "return",
            serde_json::json!({ "summary": "done", "result": "ok" }),
        );

        let flow = phase_10_dispatch_one_call(
            &agent,
            &session,
            &crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            &tx,
            &call,
            "return",
        )
        .await
        .unwrap();

        match flow {
            ControlFlow::Break(TurnOutcome::Return { fields }) => {
                assert_eq!(fields["summary"], "done");
                assert_eq!(fields["result"], "ok");
            }
            other => panic!("expected structural return break, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn phase_10_ordinary_tool_continues() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = test_agent();
        let session = test_session(tmp.path());
        let (tx, _rx) = mpsc::channel(1);
        let call = tool_call("read", serde_json::json!({ "path": "README.md" }));

        let flow = phase_10_dispatch_one_call(
            &agent,
            &session,
            &crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            &tx,
            &call,
            "read",
        )
        .await
        .unwrap();

        assert!(matches!(flow, ControlFlow::Continue(())));
    }

    #[tokio::test]
    async fn phase_10_spawn_retains_responses_dual_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut agent = test_agent();
        agent.name = "Swarm".to_string();
        agent.tools =
            ToolBox::new().with(Arc::new(crate::tools::spawn::SpawnTool::for_depth(0, 3)));
        let session = test_session(tmp.path());
        let (tx, _rx) = mpsc::channel(1);
        let provider = rig::message::ProviderCallId::new("call_spawn_1".to_string())
            .expect("provider call id")
            .with_item_id("fc_spawn_1".to_string());
        let call = ToolCall {
            id: rig::message::ToolCallId::for_provider(Some(&provider)),
            provider: Some(provider),
            function: ToolFunction {
                name: "spawn".to_string(),
                arguments: serde_json::json!({
                    "prompt": "review the child slice",
                    "write_scope": "slice"
                }),
            },
            signature: None,
            additional_params: None,
        };

        let flow = phase_10_dispatch_one_call(
            &agent,
            &session,
            &crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            &tx,
            &call,
            "spawn",
        )
        .await
        .unwrap();

        match flow {
            ControlFlow::Break(TurnOutcome::Spawn {
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
                ..
            }) => {
                assert_eq!(task_call_id, "call_spawn_1");
                assert_eq!(task_provider_item_id.as_deref(), Some("fc_spawn_1"));
                assert_eq!(task_function_call_id.as_deref(), Some("call_spawn_1"));
            }
            other => panic!("expected structural spawn break, got {other:?}"),
        }
    }

    #[test]
    fn repaired_structural_calls_replay_with_their_canonical_result_name() {
        for (emitted_name, resolved_name) in [
            ("functions.task", "task"),
            ("schedule\n", "schedule"),
            ("<spawn>", "spawn"),
        ] {
            let provider = rig::message::ProviderCallId::new("fn-structural-1".to_string())
                .expect("provider call id")
                .with_item_id("fc-structural-1".to_string());
            let call = ToolCall {
                id: rig::message::ToolCallId::for_provider(Some(&provider)),
                provider: Some(provider),
                function: ToolFunction {
                    name: emitted_name.to_string(),
                    arguments: serde_json::json!({}),
                },
                signature: None,
                additional_params: None,
            };
            let mut history = vec![Message::Assistant {
                id: None,
                content: vec![crate::engine::message::AssistantContent::ToolCall(
                    call.clone(),
                )],
            }];

            rewrite_structural_call_name_if_repaired(
                &mut history,
                &call,
                resolved_name,
                &Recovery::NameRepair {
                    stage: "rebind",
                    original: emitted_name.to_string(),
                },
            );

            let Message::Assistant { content, .. } = &history[0] else {
                panic!("expected assistant call");
            };
            let crate::engine::message::AssistantContent::ToolCall(replayed) = &content[0] else {
                panic!("expected tool call");
            };
            assert_eq!(replayed.function.name, resolved_name);
            assert_eq!(replayed.id, call.id);
            assert_eq!(replayed.provider, call.provider);

            let result =
                crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                    call.id.to_string(),
                    call.provider
                        .as_ref()
                        .and_then(|provider| provider.item_id.clone()),
                    call.provider
                        .as_ref()
                        .map(|provider| provider.call_id.clone()),
                    resolved_name,
                    "structural result",
                );
            let Message::User { content } = result else {
                panic!("expected structural result");
            };
            let UserContent::ToolResult(result) = &content[0] else {
                panic!("expected tool result");
            };
            assert_eq!(result.name, resolved_name);
            assert_eq!(result.call, call.id);
            assert_eq!(result.provider, call.provider);
        }
    }

    // ── Inference journal barrier (make-inference-journal-barrier-testable) ──

    fn inference_payload(marker: &str) -> Value {
        serde_json::json!({
            "messages": [{ "role": "user", "content": marker }]
        })
    }

    /// AC1: with the `#[cfg(test)] return Ok(None)` escape deleted, the barrier
    /// is a HARD invariant even in test builds. A session with no journal and no
    /// audited opt-out refuses the provider handoff instead of silently
    /// proceeding (the old escape would have returned `Ok(None)` here).
    #[tokio::test]
    async fn inference_journal_barrier_is_non_optional_in_test_builds() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        let model = test_model();
        let call_id = Uuid::new_v4();

        let err =
            match prepare_inference_journal(&session, &model, &inference_payload("hi"), call_id, 0)
                .await
            {
                Ok(_) => panic!("no journal + no opt-out must refuse the handoff"),
                Err(err) => err,
            };
        assert!(
            err.to_string().contains("journal is unavailable"),
            "unexpected error: {err}"
        );

        // The audited opt-out is the ONLY way to proceed without a journal.
        session.allow_unjournaled_inference(
            crate::session::UnjournaledInferenceReason::CagedSelfReviewUtility,
        );
        let attempt =
            prepare_inference_journal(&session, &model, &inference_payload("hi"), call_id, 0)
                .await
                .expect("audited opt-out proceeds without a journal");
        assert!(
            attempt.is_none(),
            "opt-out yields no journal attempt (nothing to settle)"
        );
    }

    /// AC1 + AC5: with a production-shaped journal installed, the barrier
    /// durably commits `dispatching` BEFORE returning — the only state that
    /// authorizes a provider handoff — and the persisted record is a
    /// digest-only projection that never carries the raw prompt body.
    #[tokio::test]
    async fn inference_journal_barrier_commits_dispatching_without_raw_body() {
        const SENTINEL: &str = "SENTINEL-INFERENCE-PROMPT-BODY";
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        session.install_test_external_journal();
        let model = test_model();
        let call_id = Uuid::new_v4();
        let payload = inference_payload(SENTINEL);
        // Precondition: the raw payload really carries the sentinel, so the
        // sentinel assertions below cannot pass vacuously.
        assert!(serde_json::to_string(&payload).unwrap().contains(SENTINEL));

        let attempt = prepare_inference_journal(&session, &model, &payload, call_id, 0)
            .await
            .expect("journal installed → barrier succeeds")
            .expect("journal installed → a durable attempt is produced");

        let record = session
            .db
            .external_operation(attempt.ticket.operation_id)
            .await
            .unwrap()
            .expect("durable journal record exists after the barrier");
        assert_eq!(
            record.state,
            crate::db::external_journal::ExternalJournalState::Dispatching,
            "returning from the barrier means `dispatching` is durably committed"
        );
        // AC5 sentinel: the persisted record projects only digests — the raw
        // prompt body never reaches the DB / doctor / audit surface.
        assert!(
            !format!("{record:?}").contains(SENTINEL),
            "raw inference body leaked into the persisted journal record: {record:?}"
        );
    }

    /// AC3: the opt-out is audited — every call names a reason and bumps the
    /// process-wide counter (nextest isolates each test in its own process).
    #[tokio::test]
    async fn unjournaled_opt_out_is_audited_with_reason_and_counter() {
        let tmp = tempfile::tempdir().unwrap();
        let session = test_session(tmp.path());
        assert!(session.unjournaled_inference_reason().is_none());
        let before = crate::session::unjournaled_inference_optout_count();

        session.allow_unjournaled_inference(crate::session::UnjournaledInferenceReason::DocsAsk);

        assert!(session.unjournaled_inference_allowed());
        assert_eq!(
            session.unjournaled_inference_reason(),
            Some(crate::session::UnjournaledInferenceReason::DocsAsk)
        );
        assert_eq!(
            crate::session::unjournaled_inference_optout_count(),
            before + 1,
            "each opt-out increments the audit counter exactly once"
        );
        assert_eq!(
            crate::session::UnjournaledInferenceReason::DocsAsk.as_str(),
            "docs_ask"
        );
    }
}
