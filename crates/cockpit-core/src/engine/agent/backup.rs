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
    seeds: crate::engine::seed_collector::SeedCollector,
    // Per-round-trip id, generated by the driver (shared with this turn's
    // tandem records). The primary + backup attempts use the same id — they
    // are the same logical call, one settled record.
    call_id: Uuid,
    // Model-comparison tandem (shadow) set — applied on the PRIMARY attempt
    // only (the backup retry passes `None`, so a fallback never double-shadows
    // the same logical call). implementation note.
    tandem: Option<&crate::engine::schedule::TandemSet>,
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

    let mut fallback_tried = Vec::new();
    let mut first_failure: Option<(String, crate::engine::model::InferenceErrorClass)> = None;
    let mut attempt_index = 0usize;
    loop {
        let current_model: &Model = if attempt_index == 0 {
            &agent.model
        } else {
            candidates[attempt_index - 1].as_ref()
        };
        let has_later_candidate = attempt_index < candidates.len();
        let emit_failure_ui = !has_later_candidate;
        let attempt_result = turn(
            agent,
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
            seeds.clone(),
            emit_failure_ui,
            call_id,
            if attempt_index == 0 { tandem } else { None },
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
                    if !emit_failure_ui {
                        let _ = tx
                            .send(TurnEvent::InferenceFailed {
                                agent: agent.name.clone(),
                                provider: failure.provider.clone(),
                                model: failure.model.clone(),
                                error_class: failure.class.clone(),
                                detail: failure.detail.clone(),
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
                    return Err(err);
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
    pub(super) dispatch_payload: &'a Value,
    pub(super) agent_name: &'a str,
    pub(super) wire_api: &'a str,
    pub(super) routing_metadata: Value,
    pub(super) emit_inference_error_ui: bool,
    pub(super) tx: &'a mpsc::Sender<TurnEvent>,
}

pub(super) async fn record_inference_outcome(ctx: InferenceOutcomeRecord<'_>, err: &anyhow::Error) {
    use crate::db::session_log::{InferenceRequestStatus, SessionEventKind};
    use crate::engine::model::as_inference_failure;

    let InferenceOutcomeRecord {
        session,
        call_id,
        dispatch_payload,
        agent_name,
        wire_api,
        routing_metadata,
        emit_inference_error_ui,
        tx,
    } = ctx;

    // A user cancel or daemon-drain unwind: record `cancelled` and return —
    // the driver handles these silently (no red error to the user).
    if crate::engine::model::is_cancelled(err) || crate::engine::model::is_gated(err) {
        let cancelled = with_phases(
            dispatch_payload.clone(),
            &serde_json::json!({ "dispatched_ms": 0 }),
        );
        if let Err(e) = record_inference_request_async(
            session.clone(),
            call_id,
            cancelled,
            InferenceRequestStatus::Cancelled,
        )
        .await
        {
            tracing::warn!(error = %e, "record_inference_request (cancelled) failed");
        }
        return;
    }

    let Some(failure) = as_inference_failure(err) else {
        // An unexpected error shape (not the typed seam) — still settle the
        // record to `errored` so the export isn't left at `pending`.
        let errored = with_phases(
            dispatch_payload.clone(),
            &serde_json::json!({ "dispatched_ms": 0 }),
        );
        if let Err(e) = record_inference_request_async(
            session.clone(),
            call_id,
            errored,
            InferenceRequestStatus::Errored,
        )
        .await
        {
            tracing::warn!(error = %e, "record_inference_request (errored) failed");
        }
        return;
    };

    let status = if failure.class.is_timeout() {
        InferenceRequestStatus::TimedOut
    } else {
        InferenceRequestStatus::Errored
    };
    let terminal = with_phases(
        dispatch_payload.clone(),
        &serde_json::json!({
            "dispatched_ms": 0,
            "failed_ms": failure.elapsed_ms,
        }),
    );
    if let Err(e) = record_inference_request_async(session.clone(), call_id, terminal, status).await
    {
        tracing::warn!(error = %e, "record_inference_request (terminal failure) failed");
    }

    let diagnostics = inference_failure_diagnostics(failure, wire_api);

    // Failure event (Part B): lands in the export's events.json, keyed by the
    // same call_id. Data/export only — never enters model context.
    if let Err(e) = session
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
            }),
        )
        .await
    {
        tracing::warn!(error = %e, "record inference_failure event failed");
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
        Arc::new(crate::session::Session::create(db, root.to_path_buf(), "builder").unwrap())
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
            .record_inference_request(call_id, &payload, InferenceRequestStatus::Pending)
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
                dispatch_payload: &payload,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
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
            .record_inference_request(call_id, &payload, InferenceRequestStatus::Pending)
            .await
            .unwrap();
        let (_, status) = session
            .db
            .get_inference_request(&call_id.to_string())
            .await
            .unwrap()
            .unwrap();
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
                dispatch_payload: &payload,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                tx: &tx,
            },
            &err,
        )
        .await;

        // The record settled to `timed_out` (not left at pending).
        let (_, status) = session
            .db
            .get_inference_request(&call_id.to_string())
            .await
            .unwrap()
            .unwrap();
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
            .record_inference_request(call_id, &payload, InferenceRequestStatus::Pending)
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
                dispatch_payload: &payload,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: false,
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
            .record_inference_request(call_id, &payload, InferenceRequestStatus::Pending)
            .await
            .unwrap();

        let err = anyhow::Error::new(crate::engine::model::InferenceCancelled);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        // A cancel emits no UI regardless of the flag; pass `true` to prove it.
        record_inference_outcome(
            InferenceOutcomeRecord {
                session: session.clone(),
                call_id,
                dispatch_payload: &payload,
                agent_name: "builder",
                wire_api: "responses",
                routing_metadata: serde_json::json!({}),
                emit_inference_error_ui: true,
                tx: &tx,
            },
            &err,
        )
        .await;

        let (_, status) = session
            .db
            .get_inference_request(&call_id.to_string())
            .await
            .unwrap()
            .unwrap();
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

    /// A local server that accepts requests and then stays silent long enough
    /// for the client's TTFT threshold to fire.
    async fn silent_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    let _ = stream.shutdown().await;
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
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    fn in_memory_session(root: &std::path::Path) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        Arc::new(crate::session::Session::create(db, root.to_path_buf(), "Build").unwrap())
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
            crate::engine::seed_collector::SeedCollector::new(),
            Uuid::new_v4(),
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
            crate::engine::seed_collector::SeedCollector::new(),
            Uuid::new_v4(),
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
    fn failover_walk_orders_by_trust_then_rank_after_configured_backup() {
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
                "trusted-high:trusted-high",
                "trusted-low:trusted-low"
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
            crate::engine::seed_collector::SeedCollector::new(),
            Uuid::new_v4(),
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

    #[test]
    fn failover_walk_never_promotes_untrusted_under_trusted_only() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "primary".into(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                trust: Some(ModelTrust::Trusted),
                ..ProviderEntry::default()
            },
        );
        let mut trusted = provider_with_model("http://localhost:2/v1", "trusted");
        trusted.trust = Some(ModelTrust::Trusted);
        cfg.providers.insert("trusted".into(), trusted);
        cfg.providers.insert(
            "untrusted".into(),
            provider_with_model("http://localhost:3/v1", "untrusted"),
        );
        let primary = Model::for_provider_trusted_only(
            &cfg,
            "primary",
            "primary-model",
            std::sync::Arc::new(RedactionTable::empty()),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        )
        .unwrap();
        let fallbacks = crate::engine::driver::build_failover_models(&cfg, &primary);
        assert!(
            fallbacks
                .iter()
                .all(|model| model.provider_id() != "untrusted")
        );
        assert!(
            fallbacks
                .iter()
                .any(|model| model.provider_id() == "trusted")
        );
    }

    /// A primary stream that never produces a first token times out only
    /// because a backup is configured, and the existing backup wrapper answers
    /// the turn with the backup model.
    #[tokio::test]
    async fn ttft_timeout_falls_back_to_backup_with_yellow_banner() {
        let primary_url = silent_server().await;
        let backup_url = sse_server("from-backup").await;

        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("flaky".into(), provider_at(&primary_url));
        cfg.providers
            .insert("reliable".into(), provider_at(&backup_url));
        cfg.providers.get_mut("flaky").unwrap().backup = Some(BackupConfig {
            provider: "reliable".into(),
            model: "backup-model".into(),
        });

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
        .expect("backup answers the timed-out turn");
        assert!(matches!(outcome, TurnOutcome::Done));

        let events = drain(&mut rx);
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::InferenceWarning { phase, .. } if phase == "ttft"
        )));
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
        assert_eq!(class, InferenceErrorClass::TimeoutTtft);
        assert_eq!(bm, "backup-model");
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::AssistantText { text, .. } if text.contains("from-backup")
        )));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TurnEvent::InferenceFailed { .. })),
            "the primary timeout must be suppressed when the backup answers"
        );
    }

    async fn assert_stall_hard_fails_and_engages_backup() {
        let primary_url = silent_server().await;
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
        .expect("backup answers stalled child");
        let events = drain(&mut rx);
        assert!(events.iter().any(|e| matches!(
            e,
            TurnEvent::BackupUsed { error_class, .. }
                if error_class == &InferenceErrorClass::TimeoutTtft
        )));
    }

    #[tokio::test]
    async fn delegated_child_stall_hard_fails_and_engages_failover() {
        assert_stall_hard_fails_and_engages_backup().await;
    }

    #[tokio::test]
    async fn interactive_turn_stall_hard_fails_and_engages_backup() {
        assert_stall_hard_fails_and_engages_backup().await;
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
            crate::engine::seed_collector::SeedCollector::new(),
            Uuid::new_v4(),
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
}
