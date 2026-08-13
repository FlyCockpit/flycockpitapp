use super::*;

/// Maximum models attempted for one logical turn, including the primary.
///
/// The cap is deliberately small: failover is for provider/model outages, not
/// for scanning the entire catalog while a parent model keeps issuing work.
pub const MAX_FAILOVER_CANDIDATES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FailoverAttempt {
    pub provider: String,
    pub model: String,
    pub error_class: Option<crate::engine::model::InferenceErrorClass>,
    pub outcome: &'static str,
}

impl FailoverAttempt {
    pub fn failed(model: &Model, error_class: &crate::engine::model::InferenceErrorClass) -> Self {
        Self {
            provider: model.provider_id().to_string(),
            model: model.model_id_ref().to_string(),
            error_class: Some(error_class.clone()),
            outcome: "failed",
        }
    }

    pub fn succeeded(model: &Model) -> Self {
        Self {
            provider: model.provider_id().to_string(),
            model: model.model_id_ref().to_string(),
            error_class: None,
            outcome: "succeeded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFallbackDecision {
    pub primary_model: String,
    pub error_class: crate::engine::model::InferenceErrorClass,
    pub backup_model: String,
    pub fallback_tried: Vec<FailoverAttempt>,
}

impl BackupFallbackDecision {
    pub fn routing_value(&self) -> &'static str {
        "backup"
    }
}

pub fn suggested_action_for_failure_class(
    class: &crate::engine::model::InferenceErrorClass,
) -> &'static str {
    match class {
        crate::engine::model::InferenceErrorClass::TimeoutTtft
        | crate::engine::model::InferenceErrorClass::TimeoutIdle
        | crate::engine::model::InferenceErrorClass::Network => "retry_or_choose_another_model",
        crate::engine::model::InferenceErrorClass::MissingToolEntitlement { .. }
        | crate::engine::model::InferenceErrorClass::ClientSideToolsUnsupported => {
            "change_model_or_disable_tool"
        }
        crate::engine::model::InferenceErrorClass::Http(status) if (500..=599).contains(status) => {
            "retry_later_or_choose_another_model"
        }
        crate::engine::model::InferenceErrorClass::Http(status) if (400..=499).contains(status) => {
            "check_configuration_or_credentials"
        }
        crate::engine::model::InferenceErrorClass::UtilityTimeout
        | crate::engine::model::InferenceErrorClass::ResponsesToolIdentity
        | crate::engine::model::InferenceErrorClass::ProviderNotConfigured
        | crate::engine::model::InferenceErrorClass::ProviderRateLimit
        // Treated like its ProviderRateLimit/quota sibling pending
        // harness-reliability-remediation's final policy.
        | crate::engine::model::InferenceErrorClass::BillingOrQuotaExhausted
        | crate::engine::model::InferenceErrorClass::UnrenderableWireField
        | crate::engine::model::InferenceErrorClass::Http(_)
        | crate::engine::model::InferenceErrorClass::Other(_) => "inspect_failure",
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupTurnMetadata {
    pub fallback_decision: Option<BackupFallbackDecision>,
    pub fallback_tried: Vec<FailoverAttempt>,
}

/// Run one turn with per-turn primary-first backup-model fallback
/// (implementation note).
///
/// This is the single seam both the interactive driver loop and the
/// noninteractive subagent loop run their turns through, so **every** agent —
/// the primary, `builder`, `explore`, `docs`, `Swarm` — inherits the same
/// mechanism (subagents inherit it for free; nothing is hard-coded per agent).
///
/// Behavior:
/// - Always tries the **primary** model (`&agent.model`) first. Fallback does
///   not stick — the next call (next turn) tries the primary again.
/// - On a qualifying terminal [`InferenceFailure`]
///   ([`failure_engages_backup`]) **and** a configured `backup` model, retries
///   the *same* turn on the backup. The primary's red inline error is
///   suppressed (the primary attempt ran with `emit_inference_error_ui =
///   false`); instead a display-only yellow [`TurnEvent::BackupUsed`] banner is
///   emitted, then the backup attempt runs with `emit_inference_error_ui =
///   true` so that if the **backup also fails** the user sees the standard red
///   inline error (no second banner).
/// - On a *non*-qualifying failure (e.g. `http_400`), or when no backup is
///   configured, the failure is final: the red inline error is emitted and the
///   error is returned. (Because the primary attempt suppressed its own UI when
///   a backup *might* run, this path re-emits it from here.)
///
/// The banner is **display-only**: it rides the `TurnEvent`/proto/UI plumbing
/// (never the model's history), preserving the wire-vs-user split (GOALS §14).
#[allow(clippy::too_many_arguments)]
pub async fn turn_with_backup(
    agent: &Agent,
    backup_model: Option<&Arc<Model>>,
    fallback_models: &[Arc<Model>],
    history: &mut Vec<Message>,
    prompt: Message,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    cwd: std::path::PathBuf,
    config: crate::daemon::session_worker::SessionConfigHandle,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    lsp: Option<Arc<crate::daemon::lsp::LspManager>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    is_root: bool,
    skill_write_origin: crate::skills::manage::SkillWriteOrigin,
    review_cage: Option<crate::engine::tool::ReviewCage>,
    context_usage: crate::engine::tool::ContextUsageSnapshot,
    deferred_log: crate::engine::deferred::DeferredLog,
    // Per-round-trip logical id generated by the driver and shared with the
    // primary tandem records. All attempts of this call share it; the immutable
    // per-attempt inference log distinguishes them by ordinal (primary 0, each
    // failover +1) so a terminal primary record cannot absorb the backup's
    // request body and the attempts stay correlated to one logical call.
    call_id: Uuid,
    // Model-comparison tandem (shadow) set — applied on the PRIMARY attempt
    // only (the backup retry passes `None`, so a fallback never double-shadows
    // the same logical call). implementation note.
    tandem: Option<&crate::engine::schedule::TandemSet>,
    goal_provenance: Option<(Uuid, i64)>,
    turn_id: Option<String>,
    tx: &mpsc::Sender<TurnEvent>,
    mut turn_metadata: Option<&mut BackupTurnMetadata>,
) -> Result<TurnOutcome> {
    let mut candidates: Vec<&Arc<Model>> = Vec::with_capacity(1 + fallback_models.len());
    if let Some(backup) = backup_model {
        candidates.push(backup);
    }
    for model in fallback_models {
        if candidates.len() + 1 >= MAX_FAILOVER_CANDIDATES {
            break;
        }
        let duplicate = candidates.iter().any(|candidate| {
            candidate.provider_id() == model.provider_id()
                && candidate.model_id_ref() == model.model_id_ref()
        });
        if !duplicate {
            candidates.push(model);
        }
    }

    // A trusted primary whose only candidates were untrusted has no failover
    // *because custody refused it*, not because none was configured. Compute it
    // up front: when it applies we must suppress `turn`'s own failure UI and
    // emit the augmented event ourselves, otherwise the reason never reaches
    // the user on either channel.
    let custody_block = if candidates.is_empty() {
        crate::engine::driver::failover_custody_block(&config.providers(), &agent.model)
    } else {
        None
    };

    let mut fallback_tried = Vec::new();
    let mut first_failure: Option<(String, crate::engine::model::InferenceErrorClass)> = None;
    let mut attempt_index = 0usize;
    loop {
        let current_model: &Model = if attempt_index == 0 {
            &agent.model
        } else {
            candidates[attempt_index - 1].as_ref()
        };
        // Every dispatched target renders ITS OWN effective posture AND its own
        // model-specific system context. The primary (attempt 0) already carries
        // both; each failover/backup candidate is a DIFFERENT model (and may
        // resolve a different effective mode), so re-render this child's
        // model-dependent surface (model-specific composed system + role body +
        // tool schemas/descriptions + `llm_mode`) for the candidate before the
        // turn. The toolbox (and any grants) is preserved intact — only its
        // rendering switches.
        let repostured: Option<Agent> = if attempt_index == 0 {
            None
        } else {
            let candidate_arc: &Arc<Model> = candidates[attempt_index - 1];
            let candidate_mode = config.providers().resolve_mode(
                candidate_arc.provider_id(),
                candidate_arc.model_id_ref(),
                config.extended().llm_mode,
            );
            match crate::engine::builtin::reposture_agent_for_candidate(
                agent,
                candidate_arc,
                candidate_mode,
                &session,
                &cwd,
                &session.db,
            )
            .await
            {
                Ok(reposed) => reposed,
                // Fail CLOSED: the candidate's own posture cannot be rendered, so
                // this failover candidate is NEVER dispatched under the primary's
                // posture. The def is the same for every candidate, so no later
                // candidate could re-render either — abort the whole failover with
                // the content-safe error (nothing was dispatched for this
                // candidate).
                Err(err) => return Err(err),
            }
        };
        let dispatch_agent: &Agent = repostured.as_ref().unwrap_or(agent);
        let has_later_candidate = attempt_index < candidates.len();
        // Suppress `turn`'s own red inline error when a custody block exists so
        // this function can emit the same event with the custody reason
        // appended. Without this the two paths are mutually exclusive and the
        // reason is dropped.
        let emit_failure_ui = !has_later_candidate && custody_block.is_none();
        // Every attempt of one logical call SHARES the `call_id` and takes the
        // next ordinal (primary 0, each failover +1), so the immutable
        // per-attempt inference log keeps them as distinct `(call_id, ordinal)`
        // rows that are still correlatable to one logical call. (This reverts
        // the fresh-`Uuid::new_v4()`-per-attempt workaround, which decorrelated
        // failover attempts from their primary.)
        let attempt_ordinal = attempt_index as i64;
        let attempt_result = turn(
            dispatch_agent,
            current_model,
            history,
            prompt.clone(),
            session.clone(),
            locks.clone(),
            redact.clone(),
            cwd.clone(),
            config.clone(),
            interrupts.clone(),
            cancel.clone(),
            approver.clone(),
            lsp.clone(),
            resource_scheduler.clone(),
            loop_guard_threshold,
            is_root,
            skill_write_origin,
            review_cage.clone(),
            context_usage,
            deferred_log.clone(),
            emit_failure_ui,
            call_id,
            attempt_ordinal,
            if attempt_index == 0 { tandem } else { None },
            goal_provenance,
            turn_id.clone(),
            tx,
        )
        .await;

        match attempt_result {
            Ok(outcome) => {
                if attempt_index > 0 {
                    fallback_tried.push(FailoverAttempt::succeeded(current_model));
                    if let Some(metadata) = turn_metadata.as_deref_mut() {
                        metadata.fallback_tried = fallback_tried.clone();
                        if let Some((primary_model, error_class)) = first_failure {
                            metadata.fallback_decision = Some(BackupFallbackDecision {
                                primary_model,
                                error_class,
                                backup_model: current_model.model_id_ref().to_string(),
                                fallback_tried,
                            });
                        }
                    }
                }
                return Ok(outcome);
            }
            Err(err) => {
                let Some(failure) = crate::engine::model::as_inference_failure(&err) else {
                    return Err(err);
                };
                let class = failure.class.clone();
                fallback_tried.push(FailoverAttempt::failed(current_model, &class));
                if first_failure.is_none() {
                    first_failure = Some((failure.model.clone(), class.clone()));
                }
                let can_advance = crate::engine::model::failure_engages_backup(&class)
                    && attempt_index < candidates.len();
                if !can_advance {
                    // The block only explains a failure that *would* have
                    // engaged failover; an unrelated hard error keeps its own
                    // message.
                    let applied_block = custody_block
                        .as_ref()
                        .filter(|_| crate::engine::model::failure_engages_backup(&class));
                    if !emit_failure_ui {
                        let detail = match applied_block {
                            Some(block) if failure.detail.is_empty() => block.user_message(),
                            Some(block) => {
                                format!("{}\n{}", failure.detail, block.user_message())
                            }
                            None => failure.detail.clone(),
                        };
                        let _ = tx
                            .send(TurnEvent::InferenceFailed {
                                agent: agent.name.clone(),
                                provider: failure.provider.clone(),
                                model: failure.model.clone(),
                                error_class: failure.class.clone(),
                                detail,
                                auth_failure: crate::engine::model::auth_failure_kind(failure),
                            })
                            .await;
                    }
                    if let Some(metadata) = turn_metadata.as_deref_mut() {
                        metadata.fallback_tried = fallback_tried.clone();
                        if attempt_index > 0
                            && let Some((primary_model, error_class)) = first_failure
                        {
                            metadata.fallback_decision = Some(BackupFallbackDecision {
                                primary_model,
                                error_class,
                                backup_model: current_model.model_id_ref().to_string(),
                                fallback_tried,
                            });
                        }
                    }
                    return match applied_block {
                        // Keep the original `InferenceFailure` in the chain (the
                        // driver still downcasts to it) and add the typed
                        // custody reason as context for log/report surfaces.
                        // The user-visible channel is the event above.
                        Some(block) => Err(err.context(block.user_message())),
                        None => Err(err),
                    };
                }

                let next_model = candidates[attempt_index].as_ref();
                let _ = tx
                    .send(TurnEvent::BackupUsed {
                        agent: agent.name.clone(),
                        primary_model: failure.model.clone(),
                        error_class: class,
                        backup_model: next_model.model_id_ref().to_string(),
                    })
                    .await;
                attempt_index += 1;
            }
        }
    }
}

/// Settle the dispatch-time inference record to its terminal status and
/// surface the failure (`inference-timeout-and-failure-
/// observability.md` #2/#3/#4). For a well-typed [`InferenceFailure`] (a
/// timeout / network / non-retryable HTTP error): record the terminal status
/// (`timed_out` for either timeout class, else `errored`), append an
/// `inference_failure` event carrying provider/model/phase/class/elapsed, and
/// emit the red inline `InferenceFailed` event. A clean cancel / drain unwind
/// (the `InferenceCancelled` / `InferenceGated` sentinels) records its
/// terminal status only (`cancelled`) — no red error, no failure event (the
/// driver unwinds those silently). All writes are best-effort.
pub(super) struct InferenceOutcomeRecord<'a> {
    pub(super) session: Arc<Session>,
    pub(super) call_id: Uuid,
    /// Dispatched-target attempt index of the row to settle. The immutable body
    /// was already inserted at dispatch under `(call_id, ordinal)`; settle only
    /// advances that row's status + phase columns, never its body.
    pub(super) ordinal: i64,
    pub(super) agent_name: &'a str,
    pub(super) wire_api: &'a str,
    pub(super) routing_metadata: Value,
    pub(super) emit_inference_error_ui: bool,
    pub(super) goal_provenance: Option<(Uuid, i64)>,
    pub(super) tx: &'a mpsc::Sender<TurnEvent>,
}

pub(super) async fn record_inference_outcome(ctx: InferenceOutcomeRecord<'_>, err: &anyhow::Error) {
    use crate::db::session_log::{InferencePhaseTimings, InferenceRequestStatus, SessionEventKind};
    use crate::engine::model::as_inference_failure;

    let InferenceOutcomeRecord {
        session,
        call_id,
        ordinal,
        agent_name,
        wire_api,
        routing_metadata,
        emit_inference_error_ui,
        goal_provenance,
        tx,
    } = ctx;
    // Goal provenance is stamped on the row at body-insert time; the terminal
    // settle only advances status + phase columns.
    let _ = goal_provenance;

    // A user cancel or daemon-drain unwind: record `cancelled` and return —
    // the driver handles these silently (no red error to the user).
    if crate::engine::model::is_cancelled(err) || crate::engine::model::is_gated(err) {
        if session
            .advance_inference_request(
                call_id,
                ordinal,
                InferenceRequestStatus::Cancelled,
                InferencePhaseTimings::default(),
            )
            .await
            .is_err()
        {
            tracing::warn!("primary inference audit cancellation write failed");
        }
        return;
    }

    let Some(failure) = as_inference_failure(err) else {
        // An unexpected error shape (not the typed seam) — still settle the
        // record to `errored` so the export isn't left at `pending`.
        if session
            .advance_inference_request(
                call_id,
                ordinal,
                InferenceRequestStatus::Errored,
                InferencePhaseTimings::default(),
            )
            .await
            .is_err()
        {
            tracing::warn!("primary inference audit error write failed");
        }
        return;
    };

    let status = if failure.class.is_timeout() {
        InferenceRequestStatus::TimedOut
    } else {
        InferenceRequestStatus::Errored
    };
    if session
        .advance_inference_request(
            call_id,
            ordinal,
            status,
            InferencePhaseTimings {
                failed_ms: Some(failure.elapsed_ms as i64),
                ..InferencePhaseTimings::default()
            },
        )
        .await
        .is_err()
    {
        tracing::warn!("primary inference audit failure write failed");
    }

    let diagnostics = inference_failure_diagnostics(failure, wire_api);

    // Failure event (Part B): lands in the export's events.json, keyed by this
    // attempt's call_id. Data/export only — never enters model context.
    //
    // Host/provider-authored, not model-authored: every field is failure
    // telemetry the host computed or the provider returned (provider status /
    // body snippet, host classification rationale, recommended action, timings).
    // The session model produced no output on this failed attempt, so this payload
    // carries no model-authored session-table literal. Frame-less `record_event`
    // is correct; nothing to journal.
    if session
        .record_event(
            SessionEventKind::InferenceFailure,
            Some(agent_name),
            Some(&call_id.to_string()),
            &serde_json::json!({
                "provider": failure.provider,
                "model": failure.model,
                "wire_api": wire_api,
                "routing": routing_metadata,
                "phase_reached": failure.phase,
                "error_class": failure.class,
                "elapsed_ms": failure.elapsed_ms,
                "detail": failure.detail,
                "provider_status": diagnostics.provider_status,
                "provider_body_snippet": diagnostics.provider_body_snippet,
                "retry_attempts": diagnostics.retry_attempts,
                "retry_final_decision": diagnostics.retry_final_decision,
                "classification_rationale": diagnostics.classification_rationale,
                "recommended_action": diagnostics.recommended_action,
                // Correlate this failure event to the attempt's immutable
                // `(call_id, ordinal)` inference-request row for export.
                "ordinal": ordinal,
            }),
        )
        .await
        .is_err()
    {
        tracing::warn!("inference failure audit event write failed");
    }

    // Red inline error for the user (same treatment as a ToolError). UI-only.
    // Suppressed for the *primary* attempt under the per-turn backup wrapper
    // (implementation note): the wrapper shows a yellow
    // banner on backup success instead, and emits the red error itself only
    // when there is no qualifying fallback. The DB record + failure event
    // above are written either way (data-side is unconditional).
    if emit_inference_error_ui {
        let _ = tx
            .send(TurnEvent::InferenceFailed {
                agent: agent_name.to_string(),
                provider: failure.provider.clone(),
                model: failure.model.clone(),
                error_class: failure.class.clone(),
                detail: failure.detail.clone(),
                auth_failure: crate::engine::model::auth_failure_kind(failure),
            })
            .await;
    }
}

#[derive(Debug)]
struct InferenceFailureDiagnostics {
    provider_status: Option<u16>,
    provider_body_snippet: Option<String>,
    retry_attempts: serde_json::Value,
    retry_final_decision: &'static str,
    classification_rationale: &'static str,
    recommended_action: &'static str,
}

fn inference_failure_diagnostics(
    failure: &crate::engine::model::InferenceFailure,
    _wire_api: &str,
) -> InferenceFailureDiagnostics {
    let provider_status = failure.class.provider_status();
    let provider_body_snippet = crate::text::bounded_snippet(&failure.detail, 800);
    let (retry_final_decision, classification_rationale) =
        crate::engine::retry::failure_retry_decision_and_rationale(&failure.class, provider_status);
    InferenceFailureDiagnostics {
        provider_status,
        provider_body_snippet,
        retry_attempts: serde_json::json!({
            "known": true,
            "attempts": failure.retry_attempts,
        }),
        retry_final_decision,
        classification_rationale,
        recommended_action: suggested_action_for_failure_class(&failure.class),
    }
}

#[cfg(test)]
mod inference_outcome_tests {
    //! Dispatch-time recording lifecycle (`inference-timeout-and-
    //! failure-observability.md`): a hung/failed turn settles its `pending`
    //! record to a terminal status, records a failure event, and surfaces a
    //! red inline error.
    use super::*;
    use crate::db::session_log::InferenceRequestStatus;
    use crate::engine::model::{InferenceErrorClass, InferenceFailure};

    fn in_memory_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        Arc::new(
            crate::session::Session::create(
                db,
                root.to_path_buf(),
                "builder",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        )
    }

    async fn emitted_auth_failure(
        class: InferenceErrorClass,
        detail: &str,
    ) -> Option<crate::daemon::proto::AuthFailureKind> {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "mock-model" });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();
        let err = anyhow::Error::new(InferenceFailure {
            provider: "mock-provider".into(),
            model: "mock-model".into(),
            phase: "dispatched".into(),
            class,
            elapsed_ms: 1,
            retry_attempts: 1,
            detail: detail.into(),
        });
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(4);
        record_inference_outcome(
            InferenceOutcomeRecord {
                session,
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;
        match rx.recv().await.expect("mocked failure event") {
            TurnEvent::InferenceFailed { auth_failure, .. } => auth_failure,
            event => panic!("expected inference failure, got {event:?}"),
        }
    }

    #[tokio::test]
    async fn auth_failure_classified_on_event() {
        assert_eq!(
            emitted_auth_failure(InferenceErrorClass::Http(401), "unauthorized").await,
            Some(crate::daemon::proto::AuthFailureKind::CredentialsRejected { status: 401 })
        );
    }

    #[tokio::test]
    async fn rate_limit_not_auth_failure() {
        assert_eq!(
            emitted_auth_failure(InferenceErrorClass::Http(429), "too many requests").await,
            None
        );
    }

    #[tokio::test]
    async fn timeout_settles_pending_record_and_emits_red_error() {
        // Simulate the `turn()` flow on a hang: write the dispatch-time
        // `pending` record, then a TTFT-timeout `InferenceFailure` arrives.
        // The record must settle to `timed_out`, a failure event must be
        // recorded, and a red `InferenceFailed` event must be emitted.
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "qwen3", "system": "s", "history": [] });

        // Dispatch-time write (status pending) — exactly what `turn()` does
        // before the call.
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();
        let status = session
            .db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, "pending", "the hung turn is frozen at pending");

        // The hang aborts with a TTFT timeout.
        let err = anyhow::Error::new(InferenceFailure {
            provider: "openai-compatible".into(),
            model: "qwen3".into(),
            phase: "dispatched".into(),
            class: InferenceErrorClass::TimeoutTtft,
            elapsed_ms: 120_000,
            retry_attempts: 1,
            detail: String::new(),
        })
        .context("completion call for agent `builder`");

        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;

        // The record settled to `timed_out` (not left at pending).
        let status = session
            .db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, "timed_out");

        // A failure event landed in the timeline carrying the diagnostics.
        let events = session.db.list_session_events(session.id).await.unwrap();
        let fail = events
            .iter()
            .find(|e| e.kind == "inference_failure")
            .expect("an inference_failure event was recorded");
        assert_eq!(fail.data["error_class"], serde_json::json!("timeout_ttft"));
        assert_eq!(fail.data["phase_reached"], "dispatched");
        assert_eq!(fail.data["elapsed_ms"], 120_000);
        assert_eq!(fail.data["provider"], "openai-compatible");
        assert_eq!(fail.data["model"], "qwen3");
        assert_eq!(fail.data["wire_api"], "responses");
        assert_eq!(fail.data["retry_final_decision"], "fail_fast");
        assert_eq!(
            fail.data["classification_rationale"],
            "time_to_first_token_timeout"
        );
        assert_eq!(
            fail.data["recommended_action"],
            "retry_or_choose_another_model"
        );

        // The red inline error was emitted to the UI.
        let mut saw_red = false;
        while let Ok(ev) = rx.try_recv() {
            if let TurnEvent::InferenceFailed { error_class, .. } = ev {
                assert_eq!(error_class, InferenceErrorClass::TimeoutTtft);
                saw_red = true;
            }
        }
        assert!(saw_red, "a red InferenceFailed event must reach the UI");
    }

    #[test]
    fn recommended_action_is_derived_from_failure_class() {
        assert_ne!(
            suggested_action_for_failure_class(&InferenceErrorClass::TimeoutTtft),
            suggested_action_for_failure_class(&InferenceErrorClass::Http(400))
        );
        assert_ne!(
            suggested_action_for_failure_class(&InferenceErrorClass::Http(400)),
            "retry_same_turn"
        );
    }

    #[tokio::test]
    async fn inference_failure_reports_real_retry_attempts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "mock-model" });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();
        let err = anyhow::Error::new(InferenceFailure {
            provider: "mock-provider".into(),
            model: "mock-model".into(),
            phase: "dispatched".into(),
            class: InferenceErrorClass::Network,
            elapsed_ms: 42,
            retry_attempts: 3,
            detail: "connection refused".into(),
        });
        let (tx, _rx) = mpsc::channel::<TurnEvent>(4);
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: false,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;
        let events = session.db.list_session_events(session.id).await.unwrap();
        let fail = events
            .iter()
            .find(|e| e.kind == "inference_failure")
            .expect("inference failure event");
        assert_eq!(fail.data["retry_attempts"]["known"], true);
        assert_eq!(fail.data["retry_attempts"]["attempts"], 3);
    }

    #[tokio::test]
    async fn cancel_settles_record_cancelled_without_red_error_or_event() {
        // A ctrl+c unwind (InferenceCancelled sentinel) settles the record to
        // `cancelled` and emits NO red error and NO failure event — the driver
        // unwinds those silently.
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let call_id = Uuid::new_v4();
        let payload = serde_json::json!({ "model": "m" });
        session
            .record_inference_request(
                call_id,
                &payload,
                InferenceRequestStatus::Pending,
                &crate::redact::RedactionTable::empty(),
                false,
            )
            .await
            .unwrap();

        let err = anyhow::Error::new(crate::engine::model::InferenceCancelled {
            phase: crate::engine::model::InferencePhase::Prep,
        });
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        // A cancel emits no UI regardless of the flag; pass `true` to prove it.
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                ordinal: 0,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                goal_provenance: None,
                tx: &tx,
            },
            &err,
        )
        .await;

        let status = session
            .db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .unwrap()
            .status;
        assert_eq!(status, "cancelled");
        // No failure event, no red error.
        let events = session.db.list_session_events(session.id).await.unwrap();
        assert!(!events.iter().any(|e| e.kind == "inference_failure"));
        assert!(rx.try_recv().is_err(), "no UI event on a clean cancel");
    }
}

/// End-to-end per-turn backup-model fallback tests
/// (implementation note). Each builds two real
/// `Model::OpenAi` endpoints against local TCP servers we control — one that
/// returns a terminal HTTP 500 and one that streams a valid one-token
/// chat-completions SSE response — and drives
/// [`turn_with_backup`] across them, asserting the primary-first behavior, the
/// yellow display-only banner, the backup-also-fails inline error, and that the
/// banner never enters model context.
#[cfg(test)]
mod backup_fallback_tests {
    use super::*;
    use crate::config::providers::{
        BackupConfig, ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig, TimeoutConfig,
    };
    use crate::engine::model::InferenceErrorClass;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// A local server that returns a deterministic HTTP 500. Returns the bound
    /// `base_url` (`http://127.0.0.1:PORT/v1`).
    async fn failing_server() -> String {
        failing_server_with_status(500).await
    }

    async fn failing_server_with_status(status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let body = r#"{"error":{"message":"server failed"}}"#;
                    let resp = format!(
                        "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        format!("http://{addr}/v1")
    }

    /// A local server that, for every connection, reads the request and returns
    /// a minimal valid chat-completions SSE stream: one text delta = `body`,
    /// then a finish + `[DONE]`. Returns the bound `base_url`.
    async fn sse_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    // Drain the request headers (best-effort) before replying.
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let payload = format!(
                        "data: {{\"id\":\"c\",\"model\":\"m\",\"choices\":[{{\"delta\":{{\"content\":\"{body}\"}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
                         data: {{\"id\":\"c\",\"model\":\"m\",\"choices\":[{{\"delta\":{{\"content\":\"\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\"total_tokens\":2}}}}\n\n\
                         data: [DONE]\n\n"
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        format!("http://{addr}/v1")
    }

    /// A keyless OpenAI-compat provider config at `url`.
    fn provider_at(url: &str) -> ProviderEntry {
        ProviderEntry {
            url: url.to_string(),
            headers: vec![],
            timeout: TimeoutConfig {
                ttft_secs: 1,
                idle_secs: 1,
            },
            ..ProviderEntry::default()
        }
    }

    fn provider_with_model(url: &str, model: &str) -> ProviderEntry {
        ProviderEntry {
            models: vec![ModelEntry {
                id: model.to_string(),
                subagent_invokable: Some(true),
                ..ModelEntry::default()
            }],
            ..provider_at(url)
        }
    }

    /// Build a minimal `Agent` carrying `model` and no tools (so a text-only
    /// turn ends as `Done`).
    fn agent_with(model: Arc<Model>) -> Agent {
        Agent {
            name: "Build".to_string(),
            system: "s".to_string(),
            role_prompt: "s".to_string(),
            tools: crate::engine::tool::ToolBox::new(),
            model,
            params: ModelParams::default(),
            scan_tool_results: true,
            llm_mode: crate::config::extended::LlmMode::Normal,
            lock_identity: "Build".to_string(),
            write_scope: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            assistant_identity_prefix: None,
        }
    }

    fn in_memory_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        Arc::new(
            crate::session::Session::create(
                db,
                root.to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        )
    }

    fn ctx() -> (
        tempfile::TempDir,
        Arc<Session>,
        Arc<crate::locks::LockManager>,
        Arc<RedactionTable>,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = in_memory_session(tmp.path());
        let locks = Arc::new(crate::locks::LockManager::in_memory(
            crate::db::Db::open_in_memory().unwrap(),
        ));
        let redact = Arc::new(RedactionTable::empty());
        (tmp, session, locks, redact)
    }

    async fn run(
        agent: &Agent,
        backup: Option<&Arc<Model>>,
        session: Arc<Session>,
        locks: Arc<crate::locks::LockManager>,
        redact: Arc<RedactionTable>,
        cwd: std::path::PathBuf,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<TurnOutcome> {
        turn_with_backup(
            agent,
            backup,
            &[],
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            cwd,
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            tx,
            None,
        )
        .await
    }

    /// Drain currently-buffered events into a vec (the turn is over by now).
    fn drain(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    /// AC12 — through the production failover path, each attempt's wire body is
    /// redacted for ITS OWN target and the immutable per-attempt log keeps one
    /// row per attempt whose payload byte-matches that target's wire redaction
    /// state.
    ///
    /// DIRECTION INVERSION (deliberate deviation from the AC12 wording): the
    /// prompt names a trusted-primary→untrusted-failover scenario, but that
    /// scenario is IMPOSSIBLE on the real path. Failover custody is upgrade-only
    /// ([`FailoverCustody`] / `build_failover_models_with_diagnostics`): a
    /// trusted primary REFUSES every untrusted candidate rather than re-rendering
    /// its raw trusted body onto an untrusted wire. That rejection is itself the
    /// enforcement of the "no raw trusted body reused on an untrusted wire"
    /// invariant, and it is proven directly by
    /// [`trusted_primary_refuses_untrusted_failover_and_records_it`] and
    /// [`untrusted_failover_after_trusted_primary_is_rejected_by_custody`] below.
    /// So the direction the real path permits — and the one that exercises
    /// target-specific redaction with a mixed-trust pair — is inverted here to an
    /// untrusted primary failing over to a trusted failover: the untrusted
    /// primary's wire is redacted (no sentinel), the trusted failover's wire is
    /// raw (sentinel present), both derived from the same raw history snapshot,
    /// and each stored attempt payload byte-agrees with its own captured wire
    /// body's redaction state.
    #[tokio::test]
    async fn interactive_backup_and_failover_redaction_is_target_specific() {
        use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};
        use cockpit_test_support::provider::{ScriptedProvider, Turn, Usage};

        let sentinel = "SENTINEL-SECRET-abcdef012345";

        let primary_provider = ScriptedProvider::builder()
            .turn(Turn::HttpError {
                status: 500,
                body: "boom".into(),
            })
            // Serve 500 for any internal HTTP retries too, so the attempt
            // settles to a stable Http(500) failure that engages failover.
            .repeat_last()
            .start()
            .await;
        let backup_provider = ScriptedProvider::builder()
            .turn(Turn::Text("answered by trusted failover".into()))
            .with_usage(Usage {
                prompt_tokens: 3,
                completion_tokens: 4,
                total_tokens: 7,
                use_alias_names: false,
            })
            .start()
            .await;

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: primary_provider.base_url(),
                models: vec![ModelEntry {
                    id: "primary-model".into(),
                    trust: Some(ModelTrust::Untrusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "local".into(),
            ProviderEntry {
                url: backup_provider.base_url(),
                models: vec![ModelEntry {
                    id: "backup-model".into(),
                    trust: Some(ModelTrust::Trusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        // A session table that scrubs the sentinel; each Model resolves its own
        // effective table from its custody (untrusted enforces it, trusted
        // releases the raw empty table).
        let table = Arc::new(
            RedactionTable::empty()
                .with_forced_literal(sentinel.to_string(), "$test".to_string())
                .unwrap(),
        );
        let primary =
            Arc::new(Model::for_provider(&cfg, "cloud", "primary-model", table.clone()).unwrap());
        let backup =
            Arc::new(Model::for_provider(&cfg, "local", "backup-model", table.clone()).unwrap());
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let call_id = Uuid::new_v4();

        let outcome = turn_with_backup(
            &agent,
            Some(&backup),
            &[],
            &mut Vec::new(),
            Message::user(format!("the deploy secret is {sentinel}")),
            session.clone(),
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            call_id,
            None,
            None,
            None,
            &tx,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(outcome, TurnOutcome::Done));
        let _ = drain(&mut rx);

        // Per-target wire capture (real HTTP boundary): the untrusted primary's
        // body is redacted, the trusted failover's body is raw.
        let primary_body = serde_json::to_string(&primary_provider.captured()[0].body).unwrap();
        let backup_body = serde_json::to_string(&backup_provider.captured()[0].body).unwrap();
        assert!(
            !primary_body.contains(sentinel),
            "untrusted primary wire body is redacted: {primary_body}"
        );
        assert!(
            backup_body.contains(sentinel),
            "trusted failover wire body is raw: {backup_body}"
        );

        // Two immutable attempt rows under one call_id, whose stored payloads
        // byte-match their captured wire redaction state.
        let attempts = session
            .db
            .list_inference_requests_for_call(&call_id.to_string())
            .await
            .unwrap();
        assert_eq!(attempts.len(), 2, "primary + failover both retained");
        assert_eq!(attempts[0].ordinal, 0);
        assert_eq!(attempts[0].trust.as_deref(), Some("untrusted"));
        assert!(
            !serde_json::to_string(&attempts[0].payload)
                .unwrap()
                .contains(sentinel),
            "primary row payload is redacted"
        );
        assert_eq!(attempts[1].ordinal, 1);
        assert_eq!(attempts[1].trust.as_deref(), Some("trusted"));
        assert!(
            serde_json::to_string(&attempts[1].payload)
                .unwrap()
                .contains(sentinel),
            "failover row payload is raw"
        );

        // Byte-level redaction-state agreement: each stored `(call_id, ordinal)`
        // payload agrees with its OWN captured wire body on whether the sentinel
        // is present — so the audited body is the same redaction state that hit
        // that target's wire, per target.
        let primary_stored = serde_json::to_string(&attempts[0].payload).unwrap();
        let backup_stored = serde_json::to_string(&attempts[1].payload).unwrap();
        assert_eq!(
            primary_stored.contains(sentinel),
            primary_body.contains(sentinel),
            "primary stored payload byte-matches its wire body's redaction state"
        );
        assert_eq!(
            backup_stored.contains(sentinel),
            backup_body.contains(sentinel),
            "failover stored payload byte-matches its wire body's redaction state"
        );
    }

    /// Companion to [`interactive_backup_and_failover_redaction_is_target_specific`]:
    /// the direction that test cannot exercise (trusted primary →
    /// untrusted failover) is REJECTED by the custody gate. This is the positive
    /// enforcement of the "no raw trusted body is ever re-rendered onto an
    /// untrusted wire" invariant: the untrusted candidate is refused, so no wire
    /// body for it is ever produced. (A broader recording/user-visibility proof
    /// lives in `trusted_primary_refuses_untrusted_failover_and_records_it`.)
    #[test]
    fn untrusted_failover_after_trusted_primary_is_rejected_by_custody() {
        use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "local".into(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                backup: Some(BackupConfig {
                    provider: "cloud".into(),
                    model: "cloud-model".into(),
                }),
                models: vec![ModelEntry {
                    id: "trusted-primary".into(),
                    trust: Some(ModelTrust::Trusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                models: vec![ModelEntry {
                    id: "cloud-model".into(),
                    trust: Some(ModelTrust::Untrusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        let primary = Model::for_provider(
            &cfg,
            "local",
            "trusted-primary",
            Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        assert!(primary.is_trusted());

        // The untrusted candidate is refused (custody upgrade-only), so failover
        // produces NO untrusted target — the trusted primary's raw body can never
        // be re-rendered onto an untrusted wire because there is no such wire.
        let (fallbacks, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(
            fallbacks.is_empty(),
            "no untrusted failover target may exist after a trusted primary: {:?}",
            fallbacks
                .iter()
                .map(|m| format!("{}:{}", m.provider_id(), m.model_id_ref()))
                .collect::<Vec<_>>()
        );
        assert!(
            refusals
                .iter()
                .any(|r| r.provider == "cloud" && r.model == "cloud-model"),
            "the untrusted candidate is recorded as refused: {refusals:?}"
        );
        // And the custody block is a user-visible reason for the rejection.
        assert!(
            crate::engine::driver::failover_custody_block(&cfg, &primary).is_some(),
            "a trusted primary with only untrusted candidates is custody-blocked"
        );
    }

    /// Terminal primary failure → answered by the backup, with a display-only
    /// yellow `BackupUsed` banner and NO red `InferenceFailed` for the primary.
    #[tokio::test]
    async fn terminal_failure_falls_back_to_backup_with_yellow_banner() {
        let primary_url = failing_server().await;
        let backup_url = sse_server("from-backup").await;

        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));

        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let outcome = run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await
        .expect("backup answers the turn");
        assert!(matches!(outcome, TurnOutcome::Done));

        let events = drain(&mut rx);
        // A yellow display-only banner naming primary failure + backup answer.
        let banner = events.iter().find_map(|e| match e {
            TurnEvent::BackupUsed {
                primary_model,
                error_class,
                backup_model,
                ..
            } => Some((
                primary_model.clone(),
                error_class.clone(),
                backup_model.clone(),
            )),
            _ => None,
        });
        let (pm, class, bm) = banner.expect("a BackupUsed banner was emitted");
        assert_eq!(pm, "primary-model");
        assert_eq!(class, InferenceErrorClass::Http(500));
        assert_eq!(bm, "backup-model");
        // The backup's text reached the UI.
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::AssistantText { text, .. } if text.contains("from-backup")
        )));
        // NO red inline error for the primary (it was suppressed).
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::InferenceFailed { .. })),
            "the primary's red error must be suppressed when the backup answers"
        );
    }

    #[tokio::test]
    async fn failover_walk_stops_at_candidate_cap() {
        let failing_url = failing_server().await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "flaky".into(),
            provider_with_model(&failing_url, "primary-model"),
        );
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let mut fallbacks = Vec::new();
        for idx in 0..(MAX_FAILOVER_CANDIDATES + 2) {
            let provider = format!("dead-{idx}");
            cfg.providers.insert(
                provider.clone(),
                provider_with_model(&failing_url, &format!("dead-model-{idx}")),
            );
            fallbacks.push(Arc::new(
                Model::for_provider(
                    &cfg,
                    &provider,
                    &format!("dead-model-{idx}"),
                    std::sync::Arc::new(RedactionTable::empty()),
                )
                .unwrap(),
            ));
        }

        let (tmp, session, locks, redact) = ctx();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        let mut metadata = BackupTurnMetadata::default();
        let result = turn_with_backup(
            &agent,
            None,
            &fallbacks,
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            Some(&mut metadata),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(metadata.fallback_tried.len(), MAX_FAILOVER_CANDIDATES);
    }

    #[test]
    fn failover_walk_orders_by_rank_after_configured_backup() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                backup: Some(BackupConfig {
                    provider: "explicit".into(),
                    model: "explicit-model".into(),
                }),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "explicit".into(),
            provider_with_model("http://localhost:2/v1", "explicit-model"),
        );
        let mut trusted_low = provider_with_model("http://localhost:3/v1", "trusted-low");
        trusted_low.trust = Some(ModelTrust::Trusted);
        trusted_low.quality_rank = Some(1);
        cfg.providers.insert("trusted-low".into(), trusted_low);
        let mut trusted_high = provider_with_model("http://localhost:4/v1", "trusted-high");
        trusted_high.trust = Some(ModelTrust::Trusted);
        trusted_high.quality_rank = Some(10);
        cfg.providers.insert("trusted-high".into(), trusted_high);
        let mut untrusted_best = provider_with_model("http://localhost:5/v1", "untrusted-best");
        untrusted_best.quality_rank = Some(100);
        cfg.providers
            .insert("untrusted-best".into(), untrusted_best);

        let primary = Model::for_provider(
            &cfg,
            "primary",
            "primary-model",
            std::sync::Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        let fallbacks = crate::engine::driver::build_failover_models(&cfg, &primary);
        let ids = fallbacks
            .iter()
            .map(|model| format!("{}:{}", model.provider_id(), model.model_id_ref()))
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "explicit:explicit-model",
                "untrusted-best:untrusted-best",
                "trusted-high:trusted-high"
            ]
        );
    }

    #[tokio::test]
    async fn hard_4xx_does_not_advance_failover_walk() {
        let primary_url = failing_server_with_status(400).await;
        let backup_url = sse_server("from-backup").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("bad".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "bad",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let mut metadata = BackupTurnMetadata::default();
        let result = turn_with_backup(
            &agent,
            Some(&backup),
            &[],
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            Some(&mut metadata),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(metadata.fallback_tried.len(), 1);
        let events = drain(&mut rx);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::BackupUsed { .. }))
        );
    }

    #[tokio::test]
    async fn connect_failure_surfaces_as_network_class_before_ttft_budget() {
        let backup_url = sse_server("from-backup").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("down".into(), provider_at("http://127.0.0.1:9/v1"));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "down",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);
        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await
        .expect("backup answers connection failure");
        let events = drain(&mut rx);
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::BackupUsed { error_class, .. }
                if error_class == &InferenceErrorClass::Network
        )));
    }

    /// The yellow banner is display-only and never enters model context: it
    /// rides a `TurnEvent`, not the history `Vec<Message>` the model is sent.
    #[tokio::test]
    async fn backup_banner_stays_out_of_model_context() {
        let primary_url = failing_server().await;
        let backup_url = sse_server("ok").await;

        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        let mut history: Vec<Message> = Vec::new();
        let _ = turn_with_backup(
            &agent,
            Some(&backup),
            &[],
            &mut history,
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            None,
        )
        .await
        .expect("backup answers");
        // The history the model sees carries the user turn + the backup's own
        // assistant turn — and NOTHING mentioning the fallback / primary
        // failure. No message contains a banner / "backup" annotation.
        let serialized = serde_json::to_string(&history).unwrap();
        assert!(
            !serialized.to_lowercase().contains("backup"),
            "fallback must leave no trace in model context, got: {serialized}"
        );
        assert!(
            !serialized.contains("failed"),
            "no failure annotation may enter model context"
        );
    }

    /// When the backup ALSO fails, the user sees the standard red inline error
    /// (the dependency's mechanism) and NO second banner is suppressed-away —
    /// exactly one `BackupUsed` (the attempt) then a red `InferenceFailed`.
    #[tokio::test]
    async fn backup_also_fails_surfaces_inline_error() {
        let primary_url = failing_server().await;
        let backup_url = failing_server().await; // backup fails too

        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let res = run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await;
        assert!(res.is_err(), "both models failed → the turn errors");

        let events = drain(&mut rx);
        // Exactly one yellow banner (the single backup attempt).
        let banners = events
            .iter()
            .filter(|e| matches!(e, TurnEvent::BackupUsed { .. }))
            .count();
        assert_eq!(banners, 1, "exactly one fallback attempt → one banner");
        // The backup's own failure surfaced the red inline error.
        let reds = events
            .iter()
            .filter(|e| matches!(e, TurnEvent::InferenceFailed { .. }))
            .count();
        assert_eq!(reds, 1, "the backup's failure shows the red inline error");
    }

    /// No backup configured → a primary terminal failure hard-fails with the red inline
    /// error and NO banner (the dependency's behavior is preserved).
    #[tokio::test]
    async fn no_backup_hard_fails_with_red_error() {
        let primary_url = failing_server().await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let res = run(
            &agent,
            None,
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await;
        assert!(res.is_err());
        let events = drain(&mut rx);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::BackupUsed { .. })),
            "no backup → no banner"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, TurnEvent::InferenceFailed { .. }))
                .count(),
            1,
            "no backup → the primary's red inline error fires"
        );
    }

    /// Fallback is per-turn, not sticky: a second `turn_with_backup` call tries
    /// the PRIMARY again (it answers when healthy), proving the session is
    /// never pinned to the backup.
    #[tokio::test]
    async fn fallback_is_per_turn_not_sticky() {
        // Primary streams fine this time; backup is irrelevant.
        let primary_url = sse_server("from-primary").await;
        let backup_url = sse_server("from-backup").await;
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "flaky",
                "primary-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let backup = Arc::new(
            Model::for_provider(
                &cfg,
                "reliable",
                "backup-model",
                std::sync::Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        run(
            &agent,
            Some(&backup),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            &tx,
        )
        .await
        .expect("primary answers");
        let events = drain(&mut rx);
        // The healthy primary answered — no fallback engaged.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::BackupUsed { .. })),
            "a healthy primary must answer directly (per-turn primary-first)"
        );
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::AssistantText { text, .. } if text.contains("from-primary")
        )));
    }

    /// Backup resolution is keyed purely on the running model's
    /// `(provider, model)`, so any agent (the primary, or a subagent like
    /// `builder`/`explore`/`Swarm`) running that model resolves the SAME
    /// backup — the subagent-inheritance guarantee — and the backup may name a
    /// different provider. Verified against `build_backup_model` (the shared
    /// seam every turn-runner uses).
    #[test]
    fn backup_resolution_is_model_keyed_for_subagent_inheritance() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "flaky".into(),
            ProviderEntry {
                url: "http://localhost:9/v1".into(),
                backup: Some(BackupConfig {
                    provider: "reliable".into(),
                    model: "backup-model".into(),
                }),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "reliable".into(),
            ProviderEntry {
                url: "http://localhost:8/v1".into(),
                models: vec![ModelEntry {
                    id: "backup-model".into(),
                    subagent_invokable: Some(true),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let running = Model::for_provider(
            &cfg,
            "flaky",
            "primary-model",
            std::sync::Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        let backup = crate::engine::driver::build_backup_model(&cfg, &running)
            .expect("a backup resolves for the running model");
        // The resolved backup points at the DIFFERENT configured provider/model
        // — independent of which agent is running `running`.
        assert_eq!(backup.provider_id(), "reliable");
        assert_eq!(backup.model_id_ref(), "backup-model");
    }

    /// Decision (B), untrusted primary: failover may upgrade onto a trusted
    /// (self-hosted / no-log) endpoint, and may stay untrusted. Nothing is
    /// refused, so no custody diagnostic is recorded.
    #[test]
    fn untrusted_primary_may_fail_over_to_trusted_or_untrusted() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            provider_with_model("http://localhost:1/v1", "main"),
        );
        let mut trusted = provider_with_model("http://localhost:2/v1", "trusted-candidate");
        trusted.trust = Some(ModelTrust::Trusted);
        cfg.providers.insert("trusted".into(), trusted);
        let mut untrusted = provider_with_model("http://localhost:3/v1", "untrusted-candidate");
        untrusted.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("untrusted".into(), untrusted);

        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();
        let (fallbacks, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        let ids: Vec<String> = fallbacks
            .iter()
            .map(|model| format!("{}:{}", model.provider_id(), model.model_id_ref()))
            .collect();

        assert!(
            ids.iter().any(|id| id == "trusted:trusted-candidate"),
            "an upgrade onto a trusted endpoint is permitted: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| id == "untrusted:untrusted-candidate"),
            "staying at the primary's own class is permitted: {ids:?}"
        );
        assert!(refusals.is_empty(), "nothing to refuse: {refusals:?}");
    }

    /// Decision (B), trusted primary: failover is upgrade-only, so an untrusted
    /// candidate is refused with a typed error and recorded — never a silent
    /// downgrade onto a cloud endpoint. A trusted primary with no trusted
    /// candidate ends with an empty candidate list.
    #[test]
    fn trusted_primary_refuses_untrusted_failover_and_records_it() {
        let mut cfg = ProvidersConfig::default();
        let mut primary_entry = provider_with_model("http://localhost:1/v1", "main");
        primary_entry.trust = Some(ModelTrust::Trusted);
        primary_entry.backup = Some(BackupConfig {
            provider: "cloud".into(),
            model: "cloud-model".into(),
        });
        cfg.providers.insert("primary".into(), primary_entry);
        let mut cloud = provider_with_model("http://localhost:2/v1", "cloud-model");
        cloud.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("cloud".into(), cloud);

        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        // The configured backup is refused rather than substituted.
        let (backup, backup_refusal) =
            crate::engine::driver::build_backup_model_with_diagnostics(&cfg, &primary);
        assert!(backup.is_none(), "a downgrade must not be substituted");
        let backup_refusal = backup_refusal.expect("the refusal must be recorded");
        assert_eq!(backup_refusal.provider, "cloud");
        assert_eq!(backup_refusal.model, "cloud-model");
        assert!(
            backup_refusal.reason.contains("upgrade-only"),
            "{}",
            backup_refusal.reason
        );

        // Discovery finds no admissible candidate either: typed failure, empty list.
        let (fallbacks, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(fallbacks.is_empty(), "no trusted candidate exists");
        assert!(
            refusals
                .iter()
                .any(|refusal| refusal.provider == "cloud" && refusal.model == "cloud-model"),
            "every refused candidate is recorded: {refusals:?}"
        );

        // Adding a trusted candidate restores failover — the upgrade path works.
        let mut trusted = provider_with_model("http://localhost:3/v1", "trusted-candidate");
        trusted.trust = Some(ModelTrust::Trusted);
        cfg.providers.insert("trusted".into(), trusted);
        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();
        let (fallbacks, _) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(
            fallbacks.iter().any(|model| {
                model.provider_id() == "trusted" && model.model_id_ref() == "trusted-candidate"
            }),
            "a trusted candidate is admissible for a trusted primary"
        );
    }

    /// The typed custody refusal must reach the session boundary as a
    /// user-visible reason. Without it the user sees only the primary's
    /// original inference error and cannot tell that failover existed but was
    /// refused on custody grounds.
    #[test]
    fn trusted_primary_custody_block_is_a_user_visible_reason() {
        let mut cfg = ProvidersConfig::default();
        let mut primary_entry = provider_with_model("http://localhost:1/v1", "main");
        primary_entry.trust = Some(ModelTrust::Trusted);
        primary_entry.backup = Some(BackupConfig {
            provider: "cloud".into(),
            model: "cloud-model".into(),
        });
        cfg.providers.insert("primary".into(), primary_entry);
        let mut cloud = provider_with_model("http://localhost:2/v1", "cloud-model");
        cloud.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("cloud".into(), cloud);

        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        let block = crate::engine::driver::failover_custody_block(&cfg, &primary)
            .expect("a trusted primary with only untrusted candidates is custody-blocked");
        assert_eq!(block.primary_provider, "primary");
        assert_eq!(block.primary_model, "main");
        assert!(
            block
                .refused
                .iter()
                .all(|refusal| refusal.kind.is_custody()),
            "only custody refusals belong in the block: {:?}",
            block.refused
        );
        let message = block.user_message();
        assert!(message.contains("no failover target"), "{message}");
        assert!(message.contains("upgrade-only"), "{message}");
        assert!(message.contains("cloud:cloud-model"), "{message}");
        assert!(message.contains("Configure a trusted backup"), "{message}");

        // An untrusted primary is never custody-blocked — failover may upgrade.
        let mut untrusted_cfg = cfg.clone();
        untrusted_cfg.providers.get_mut("primary").unwrap().trust = Some(ModelTrust::Untrusted);
        let untrusted_primary = Model::for_provider(
            &untrusted_cfg,
            "primary",
            "main",
            Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        assert!(
            crate::engine::driver::failover_custody_block(&untrusted_cfg, &untrusted_primary)
                .is_none()
        );

        // Nor is a trusted primary that has an admissible trusted candidate.
        let mut ok_cfg = cfg.clone();
        let mut trusted = provider_with_model("http://localhost:3/v1", "trusted-candidate");
        trusted.trust = Some(ModelTrust::Trusted);
        ok_cfg.providers.insert("trusted".into(), trusted);
        let ok_primary = Model::for_provider(
            &ok_cfg,
            "primary",
            "main",
            Arc::new(RedactionTable::empty()),
        )
        .unwrap();
        assert!(crate::engine::driver::failover_custody_block(&ok_cfg, &ok_primary).is_none());
    }

    /// Item 2 (round 4). The typed custody reason must actually reach the user
    /// through `turn_with_backup`, not just format correctly.
    ///
    /// Previously `emit_failure_ui` and the custody-block branch were mutually
    /// exclusive — an empty candidate list forced `emit_failure_ui = true`, so
    /// `turn` emitted the plain error and the augmented event never ran. This
    /// drives a real trusted primary against a failing endpoint and asserts the
    /// `InferenceFailed` event the user sees carries the custody reason.
    #[tokio::test]
    async fn trusted_primary_custody_block_reaches_the_inference_failed_event() {
        let failing_url = failing_server().await;
        let mut cfg = ProvidersConfig::default();
        let mut primary_entry = provider_with_model(&failing_url, "primary-model");
        primary_entry.trust = Some(ModelTrust::Trusted);
        primary_entry.backup = Some(BackupConfig {
            provider: "cloud".into(),
            model: "cloud-model".into(),
        });
        cfg.providers.insert("primary".into(), primary_entry);
        let mut cloud = provider_with_model(&failing_url, "cloud-model");
        cloud.trust = Some(ModelTrust::Untrusted);
        cfg.providers.insert("cloud".into(), cloud);

        let primary = Arc::new(
            Model::for_provider(
                &cfg,
                "primary",
                "primary-model",
                Arc::new(RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = agent_with(primary);

        // The custody refusal means there is no candidate to hand in.
        let (fallbacks, _) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &agent.model);
        assert!(fallbacks.is_empty(), "custody refused every candidate");

        let (tmp, session, locks, redact) = ctx();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                cfg.clone(),
                crate::config::extended::ExtendedConfig::default(),
            ),
        );
        let result = turn_with_backup(
            &agent,
            None,
            &fallbacks,
            &mut Vec::new(),
            Message::user("hi"),
            session,
            locks,
            redact,
            tmp.path().to_path_buf(),
            config,
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            tokio_util::sync::CancellationToken::new(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            Uuid::new_v4(),
            None,
            None,
            None,
            &tx,
            None,
        )
        .await;
        assert!(result.is_err(), "the primary fails and has no failover");
        // The error chain still carries the typed reason for log/report surfaces.
        assert!(
            format!("{:#}", result.unwrap_err()).contains("upgrade-only"),
            "the custody reason must ride the error chain too"
        );

        drop(tx);
        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        let detail = events
            .iter()
            .find_map(|event| match event {
                TurnEvent::InferenceFailed { detail, .. } => Some(detail.clone()),
                _ => None,
            })
            .expect("the user-visible red inline error is emitted exactly once");
        assert!(detail.contains("no failover target"), "{detail}");
        assert!(detail.contains("upgrade-only"), "{detail}");
        assert!(detail.contains("cloud:cloud-model"), "{detail}");
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TurnEvent::InferenceFailed { .. }))
                .count(),
            1,
            "exactly one red error — `turn`'s own emit must be suppressed"
        );
    }

    /// Eligibility rejections are never recorded or logged as custody refusals.
    #[test]
    fn eligibility_rejections_are_not_labelled_as_custody() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            provider_with_model("http://localhost:1/v1", "main"),
        );
        cfg.providers.insert(
            "candidate".into(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                models: vec![ModelEntry {
                    id: "missing-context".into(),
                    subagent_invokable: Some(true),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        let (_, refusals) =
            crate::engine::driver::build_failover_models_with_diagnostics(&cfg, &primary);
        assert!(
            refusals
                .iter()
                .all(|refusal| refusal.kind.as_str() != "custody_downgrade"),
            "an untrusted primary can never produce a custody refusal: {refusals:?}"
        );
    }

    #[test]
    fn failover_discovery_includes_an_untrusted_invokable_model() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            provider_with_model("http://localhost:1/v1", "main"),
        );
        cfg.providers.insert(
            "candidate".into(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                models: vec![ModelEntry {
                    id: "untrusted".into(),
                    subagent_invokable: Some(true),
                    trust: Some(ModelTrust::Untrusted),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let primary =
            Model::for_provider(&cfg, "primary", "main", Arc::new(RedactionTable::empty()))
                .unwrap();

        let fallbacks = crate::engine::driver::build_failover_models(&cfg, &primary);

        assert!(fallbacks.iter().any(|model| {
            model.provider_id() == "candidate" && model.model_id_ref() == "untrusted"
        }));
    }
}
