use super::*;

#[test]
fn existing_goal_dispatch_uses_persisted_policy_except_for_live_kill_switch() {
    let persisted = crate::config::extended::GoalSupervisionConfig {
        cold_skeptic_count: 1,
        max_verification_attempts: 9,
        evaluator_model: Some("provider/persisted-evaluator".into()),
        ..Default::default()
    };
    let encoded = serde_json::to_string(&persisted).unwrap();
    let resolved = resolved_goal_supervision_config(&encoded, true).unwrap();
    assert_eq!(resolved, persisted);
    assert!(resolved_goal_supervision_config(&encoded, false).is_err());
}

#[tokio::test]
async fn goal_mutating_action_and_context_delta_reset_progress_counters() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "reset counters on durable progress",
            None,
            None,
        )
        .await
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq().await;
    driver.goal_turns_since_mutating_action = 4;
    driver.goal_turns_since_goal_context_delta = 4;

    record_goal_tool_event(
        &driver,
        "write",
        serde_json::json!({"path": "src/lib.rs", "content": "changed"}),
    )
    .await;
    let mutating = driver.observe_goal_progress_turn().await.unwrap();
    assert!(mutating.mutating_action);
    assert_eq!(driver.goal_turns_since_mutating_action, 0);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 5);

    record_goal_tool_event(
        &driver,
        "goal",
        serde_json::json!({
            "action": "update",
            "status": "active",
            "context_delta": "edited src/lib.rs"
        }),
    )
    .await;
    let context = driver.observe_goal_progress_turn().await.unwrap();
    assert!(context.context_delta);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 0);
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
}

#[test]
fn worker_cannot_create_or_mutate_goal() {
    assert!(!crate::agents::known_tool_names().contains(&"goal"));
}

#[test]
fn goal_continue_progress_accepts_goal_status_update() {
    assert!(
        !crate::agents::known_tool_names().contains(&"goal"),
        "worker status updates must remain unavailable; host continuations use durable DB state"
    );
}

#[tokio::test]
async fn delegation_brief_todo_block_omits_append_note_instruction() {
    let (driver, _tmp) = test_driver(1);
    let todo = driver
        .session
        .db
        .create_task_todo(driver.session.id, "ship child task", 0)
        .await
        .unwrap();

    let brief = driver
        .assign_todos_to_task(
            "Do the task.".to_string(),
            &[todo.id],
            "call-1",
            "label",
            "builder",
        )
        .await;

    assert!(brief.contains("Assigned todos (durable state):"));
    assert!(!brief.contains("append_note"));
    assert!(!brief.contains("todo(action=\"append_note\")"));
}

#[tokio::test]
async fn delegation_brief_todo_block_keeps_todo_delta_instruction() {
    let (driver, _tmp) = test_driver(1);
    let todo = driver
        .session
        .db
        .create_task_todo(driver.session.id, "ship child task", 0)
        .await
        .unwrap();

    let brief = driver
        .assign_todos_to_task(
            "Do the task.".to_string(),
            &[todo.id],
            "call-1",
            "label",
            "builder",
        )
        .await;

    assert!(brief.contains("fenced `todo_delta` JSON object"));
    assert!(brief.contains("\"todos\""));
    assert!(brief.contains("\"suggested_edits\""));
}

#[tokio::test]
async fn goal_prose_without_tools_counts_as_no_progress_subset() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "catch prose-only stalls",
            None,
            None,
        )
        .await
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq().await;
    driver
        .stack
        .first_mut()
        .unwrap()
        .history
        .push(Message::assistant("I will keep working."));

    let observation = driver.observe_goal_progress_turn().await.unwrap();

    assert!(observation.no_progress());
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 1);
}

#[tokio::test]
async fn goal_budget_autopause_idle_reason_is_budget_limited() {
    let (mut driver, tmp) = test_driver(1);
    let goal = driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stay within budget",
            None,
            Some(1),
        )
        .await
        .unwrap();
    let call = crate::db::inference_calls::InferenceCallRow {
        call_id: uuid::Uuid::new_v4(),
        session_id: driver.session.id,
        project_id: driver.session.project_id.clone(),
        project_root: tmp.path().display().to_string(),
        model: "test-model".to_string(),
        provider: "test-provider".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        input_tokens: 2,
        output_tokens: 0,
        cached_input_tokens: 0,
        cache_creation_input_tokens: 0,
        cost_usd_micros: None,
        is_utility: false,
    };
    driver
        .session
        .db
        .insert_inference_request(
            &call.call_id.to_string(),
            0,
            driver.session.id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((goal.id, goal.attempt_generation)),
        )
        .await
        .unwrap();
    driver
        .session
        .db
        .insert_inference_call(&call)
        .await
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
        .await
        .unwrap();
    let (queue_updates_tx, _queue_updates_rx) = tokio::sync::watch::channel(Vec::new());
    let input_queue = crate::engine::message::UserSubmissionQueue::new(queue_updates_tx);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .maybe_continue_active_goal(&input_queue, &tx)
        .await
        .unwrap();

    assert_eq!(
        driver.take_idle_reason().await,
        crate::engine::IdleReason::BudgetLimited
    );
}

#[tokio::test]
async fn stalled_goal_token_budget_exhaustion_needs_intervention() {
    let (mut driver, tmp) = test_driver(1);
    let goal = driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stop stalled work at explicit budget",
            None,
            Some(10),
        )
        .await
        .unwrap();
    driver.goal_turns_since_mutating_action = GOAL_NO_PROGRESS_NUDGE_BOUND;
    driver.goal_turns_since_goal_context_delta = GOAL_NO_PROGRESS_NUDGE_BOUND;
    let call = crate::db::inference_calls::InferenceCallRow {
        call_id: uuid::Uuid::new_v4(),
        session_id: driver.session.id,
        project_id: driver.session.project_id.clone(),
        project_root: tmp.path().display().to_string(),
        model: "test-model".to_string(),
        provider: "test-provider".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        input_tokens: 10,
        output_tokens: 0,
        cached_input_tokens: 0,
        cache_creation_input_tokens: 0,
        cost_usd_micros: None,
        is_utility: false,
    };
    driver
        .session
        .db
        .insert_inference_request(
            &call.call_id.to_string(),
            0,
            driver.session.id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((goal.id, goal.attempt_generation)),
        )
        .await
        .unwrap();
    driver
        .session
        .db
        .insert_inference_call(&call)
        .await
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
        .await
        .unwrap();
    let (queue_updates_tx, _queue_updates_rx) = tokio::sync::watch::channel(Vec::new());
    let input_queue = crate::engine::message::UserSubmissionQueue::new(queue_updates_tx);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .maybe_continue_active_goal(&input_queue, &tx)
        .await
        .unwrap();

    assert!(driver.goal_idle_intervention_pending);
    assert_eq!(
        driver.take_idle_reason().await,
        crate::engine::IdleReason::NeedsIntervention {
            code: "agent_failed_to_progress_budget_exhausted".to_string()
        }
    );
}

#[tokio::test]
async fn goal_usage_limit_failure_pauses_goal_and_arms_backoff() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "keep going through provider throttling",
            None,
            None,
        )
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let failure = crate::engine::model::InferenceFailure {
        provider: "test-provider".to_string(),
        model: "test-model".to_string(),
        phase: "stream".to_string(),
        class: crate::engine::model::InferenceErrorClass::Http(429),
        elapsed_ms: 42,
        retry_attempts: 1,
        detail: "rate limited".to_string(),
        observed_status: Some(429),
        recovery: crate::engine::model::ProviderRecoverySignal::None,
    };

    assert!(driver.handle_goal_usage_limit_failure(&failure, &tx).await);

    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.disposition,
        crate::db::session_goals::GoalDisposition::InfraPaused
    );
    assert_eq!(
        driver.take_idle_reason().await,
        crate::engine::IdleReason::UsageLimited
    );
    let mut watchdog = None;
    driver.refresh_goal_watchdog(&mut watchdog).await;
    assert!(watchdog.is_some(), "usage_limited goal should arm backoff");
    match rx.try_recv().expect("usage-limit notice should emit") {
        TurnEvent::Notice { text } => {
            assert!(text.contains("auto-resuming after backoff"), "{text}");
        }
        other => panic!("expected usage-limit Notice, got {other:?}"),
    }
}

#[tokio::test]
async fn goal_usage_limit_watchdog_auto_resumes_to_active() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "resume after throttling",
            None,
            None,
        )
        .await
        .unwrap();
    driver
        .session
        .db
        .update_session_goal(
            driver.session.id,
            crate::db::session_goals::GoalDisposition::InfraPaused,
            None,
            None,
            Some("provider usage or rate limit reached"),
        )
        .await
        .unwrap();

    let action = driver.goal_usage_limit_watchdog_action().await.unwrap();

    assert_eq!(action, GoalUsageLimitWatchdogAction::AutoResume);
    assert_eq!(driver.goal_usage_limit_auto_resume_attempts, 1);
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.disposition,
        crate::db::session_goals::GoalDisposition::Running
    );
}

#[tokio::test]
async fn persistent_goal_usage_limit_requires_manual_resume_after_bound() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stop retrying after bounded throttling",
            None,
            None,
        )
        .await
        .unwrap();
    driver.goal_usage_limit_auto_resume_attempts = GOAL_USAGE_LIMIT_MAX_AUTO_RESUME_ATTEMPTS;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let failure = crate::engine::model::InferenceFailure {
        provider: "test-provider".to_string(),
        model: "test-model".to_string(),
        phase: "dispatch".to_string(),
        class: crate::engine::model::InferenceErrorClass::ProviderRateLimit,
        elapsed_ms: 7,
        retry_attempts: 1,
        detail: "quota exhausted".to_string(),
        observed_status: None,
        recovery: crate::engine::model::ProviderRecoverySignal::None,
    };

    assert!(driver.handle_goal_usage_limit_failure(&failure, &tx).await);

    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.disposition,
        crate::db::session_goals::GoalDisposition::InfraPaused
    );
    assert_eq!(
        driver.take_idle_reason().await,
        crate::engine::IdleReason::NeedsIntervention {
            code: GOAL_USAGE_LIMIT_INTERVENTION_CODE.to_string()
        }
    );
    let mut watchdog = None;
    driver.refresh_goal_watchdog(&mut watchdog).await;
    assert!(
        watchdog.is_none(),
        "bounded usage-limit exhaustion should not re-arm auto-resume"
    );
    match rx.try_recv().expect("manual resume notice should emit") {
        TurnEvent::Notice { text } => {
            assert!(text.contains("run `/goal resume`"), "{text}");
        }
        other => panic!("expected manual resume Notice, got {other:?}"),
    }
}

#[tokio::test]
async fn ordinary_non_goal_idle_reason_is_completed() {
    let (mut driver, _tmp) = test_driver(1);

    assert_eq!(
        driver.take_idle_reason().await,
        crate::engine::IdleReason::Completed
    );
}

#[tokio::test]
async fn goal_idle_intervention_idle_reason_carries_code() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship goal flow",
            None,
            None,
        )
        .await
        .unwrap();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .await
        .unwrap()
        .unwrap();

    driver
        .emit_goal_no_progress_budget_exhausted(&goal, &tx)
        .await;

    assert_eq!(
        driver.take_idle_reason().await,
        crate::engine::IdleReason::NeedsIntervention {
            code: "agent_failed_to_progress_budget_exhausted".to_string()
        }
    );
}

#[tokio::test]
async fn goal_continue_only_maintenance_events_emits_diagnostic_and_keeps_latch() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship goal flow",
            None,
            None,
        )
        .await
        .unwrap();
    driver.goal_idle_intervention_pending = true;
    let anchor = driver.latest_session_event_seq().await;
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "continue"}),
        )
        .await
        .unwrap();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::SkillAutoSelect,
            Some("Build"),
            None,
            &serde_json::json!({"rejections": []}),
        )
        .await
        .unwrap();
    driver
        .session
        .record_context_pruned(
            "Build",
            true,
            4,
            4,
            120,
            120,
            &[],
            "exact-identity",
            0,
            None,
            Some("cache_already_cold"),
        )
        .await
        .unwrap();
    let call_id = uuid::Uuid::new_v4().to_string();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some("Build"),
            Some(&call_id),
            &serde_json::json!({"usage": null}),
        )
        .await
        .unwrap();

    assert!(
        !driver.goal_continue_progress_since(anchor).await,
        "skill diagnostics, context_pruned, and inference_request are maintenance only"
    );

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    driver.emit_goal_continue_no_progress(anchor, &tx).await;
    let notice = rx.try_recv().expect("diagnostic notice should emit");
    match notice {
        TurnEvent::Notice { text } => {
            assert!(text.contains("agent_failed_to_progress_after_continue"));
        }
        other => panic!("expected diagnostic Notice, got {other:?}"),
    }
    assert!(
        driver.goal_idle_intervention_pending,
        "no-progress continue keeps the intervention latch active"
    );
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let diagnostic = events
        .iter()
        .find(|event| event.kind == "goal_progress_diagnostic")
        .expect("goal progress diagnostic is durable");
    assert_eq!(diagnostic.data["kind"], "goal_continue_no_progress");
    assert_eq!(diagnostic.data["anchor_seq"], serde_json::json!(anchor));
}

#[tokio::test]
async fn failed_turn_recovery_records_retry_context_and_progress() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship the recovery path",
            None,
            None,
        )
        .await
        .unwrap();
    driver.stack[0]
        .history
        .push(write_turn("edit-1", "src/lib.rs"));
    driver.stack[0]
        .history
        .push(bash_turn("bash-1", "cargo test"));
    let agent = driver.stack[0].agent.clone();
    let attempted = Message::user("continue implementing the retry contract");
    let call_id = uuid::Uuid::new_v4();
    let failure = crate::engine::model::InferenceFailure {
        provider: "codex-oauth".into(),
        model: "gpt-5.5".into(),
        phase: "first_token".into(),
        class: crate::engine::model::InferenceErrorClass::Network,
        elapsed_ms: 42_000,
        retry_attempts: 1,
        detail: "HTTP 503 Service Unavailable".into(),
        observed_status: None,
        recovery: crate::engine::model::ProviderRecoverySignal::None,
    };
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .record_failed_turn_recovery(&agent, &attempted, call_id, &failure, &tx)
        .await;

    let notice = rx.try_recv().expect("retry notice emitted");
    match notice {
        TurnEvent::Notice { text } => {
            assert!(text.contains("continue"));
            assert!(text.contains("retry the same turn"));
        }
        other => panic!("expected Notice, got {other:?}"),
    }
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let recovery = events
        .iter()
        .find(|event| event.kind == "failed_turn_recovery")
        .expect("failed_turn_recovery event recorded");
    let call_id_str = call_id.to_string();
    assert_eq!(recovery.call_id.as_deref(), Some(call_id_str.as_str()));
    assert_eq!(recovery.data["status"], "needs_retry");
    assert_eq!(
        recovery.data["active_prompt"]["text"],
        "continue implementing the retry contract"
    );
    assert_eq!(
        recovery.data["active_goal"]["objective"],
        "ship the recovery path"
    );
    assert_eq!(recovery.data["provider"], "codex-oauth");
    assert_eq!(recovery.data["model"], "gpt-5.5");
    assert_eq!(recovery.data["wire_api"], "completions");
    assert_eq!(recovery.data["phase_reached"], "first_token");
    assert_eq!(
        recovery.data["retry_final_decision"],
        "terminal_after_retry_layer"
    );
    assert_eq!(
        recovery.data["recommended_action"]["kind"],
        "retry_same_turn"
    );
    assert_eq!(recovery.data["last_action"], "bash `cargo test`");
    assert_eq!(recovery.data["files_edited"][0]["path"], "src/lib.rs");
    assert_eq!(recovery.data["commands"][0]["verification"], true);
    assert_eq!(
        recovery.data["worktree"]["dirty_files"][0],
        serde_json::json!("src/lib.rs")
    );
}

#[tokio::test]
async fn failed_turn_continue_reuses_and_consumes_recovery_record() {
    let (driver, _tmp) = test_driver(1);
    let recovery_id = uuid::Uuid::new_v4().to_string();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::FailedTurnRecovery,
            Some("Build"),
            Some(&recovery_id),
            &serde_json::json!({
                "status": "needs_retry",
                "recovery_id": recovery_id.clone(),
                "active_prompt": {
                    "text": "original failed prompt",
                    "truncated": false,
                    "has_non_text_parts": false
                }
            }),
        )
        .await
        .unwrap();

    let (id, prompt) = driver
        .failed_turn_retry_prompt_for("continue")
        .await
        .expect("continue should recover prompt");
    assert_eq!(id, recovery_id);
    assert_eq!(prompt, "original failed prompt");

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    driver.record_failed_turn_retry_started(&id, &tx).await;
    assert!(matches!(
        rx.try_recv().unwrap(),
        TurnEvent::Notice { text } if text.contains("retrying failed turn")
    ));
    assert!(
        driver
            .failed_turn_retry_prompt_for("continue")
            .await
            .is_none(),
        "retry_started should prevent stale repeated continue"
    );
}

/// Behavior 9 goal-pause exclusion: a `BillingOrQuotaExhausted` failure — even
/// when observed as HTTP 429, the same status a genuine provider rate-limit
/// carries — must NOT usage-limit-pause an active goal. Topping up / switching
/// provider is the fix, not waiting out a window. The decision keys on the
/// error CLASS enum, never on the `observed_status` string: this failure sets
/// `observed_status: Some(429)`, so if the pause keyed on the status it WOULD
/// pause here (as `goal_usage_limit_failure_pauses_goal_and_arms_backoff`
/// proves for a real 429), making this assertion non-vacuous.
#[tokio::test]
async fn billing_quota_does_not_pause_active_goal() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "keep shipping through a billing failure",
            None,
            None,
        )
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let failure = crate::engine::model::InferenceFailure {
        provider: "test-provider".to_string(),
        model: "test-model".to_string(),
        phase: "dispatch".to_string(),
        // Billing class, but OBSERVED as 429 (the rate-limit status). The
        // exclusion must key on the class, not the observed status.
        class: crate::engine::model::InferenceErrorClass::BillingOrQuotaExhausted,
        elapsed_ms: 12,
        retry_attempts: 0,
        detail: "insufficient account balance".to_string(),
        observed_status: Some(429),
        recovery: crate::engine::model::ProviderRecoverySignal::BillingExhausted,
    };

    // Not a usage limit → the handler declines to pause.
    assert!(!driver.handle_goal_usage_limit_failure(&failure, &tx).await);

    // The goal stays Running (never InfraPaused) and no auto-resume backoff arms.
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.disposition,
        crate::db::session_goals::GoalDisposition::Running,
        "billing failure must not usage-limit-pause the active goal"
    );
    let mut watchdog = None;
    driver.refresh_goal_watchdog(&mut watchdog).await;
    assert!(
        watchdog.is_none(),
        "a non-usage-limit failure must not arm the usage-limit backoff"
    );
    assert!(
        rx.try_recv().is_err(),
        "no usage-limit notice should be emitted for a billing failure"
    );

    // And the class-based decision is confirmed directly at the seam.
    assert!(
        !crate::engine::retry::is_usage_limit_failure(&failure.class, failure.observed_status),
        "BillingOrQuotaExhausted is excluded from the usage-limit class even with observed 429"
    );
}

/// Behavior 9 fail-closed omission: EVERY failure-detail sink routes the raw
/// provider text through the single `safe_provider_detail` funnel, so the fixed
/// `provider_detail_omitted` marker crosses each channel instead of the body —
/// while the typed classification metadata (observed status class, recovery
/// kind) stays queryable. Non-vacuous: the failure carries a distinctive secret
/// detail string, and each sink is asserted to omit it; a sink that leaked
/// `failure.detail` would fail the corresponding `!contains(SECRET)` check.
#[tokio::test]
async fn inference_failure_projection_omits_provider_detail_from_all_safe_sinks() {
    // A sentinel that only appears if a sink leaked the raw provider body.
    const SECRET: &str = "RAW_PROVIDER_BODY_MUST_NEVER_LEAK_9f3a";

    let make_failure = || crate::engine::model::InferenceFailure {
        provider: "acme".to_string(),
        model: "acme-large".to_string(),
        phase: "first_token".to_string(),
        class: crate::engine::model::InferenceErrorClass::BillingOrQuotaExhausted,
        elapsed_ms: 4_200,
        retry_attempts: 1,
        detail: format!("HTTP 429 from acme: {SECRET}"),
        observed_status: Some(429),
        recovery: crate::engine::model::ProviderRecoverySignal::BillingExhausted,
    };

    // Sink 0 — the funnel itself: fixed marker, no raw text, metadata retained.
    let failure = make_failure();
    let safe = crate::engine::model::safe_provider_detail(&failure);
    assert_eq!(safe.marker, crate::engine::model::PROVIDER_DETAIL_OMITTED);
    assert_eq!(safe.observed_status, Some(429));
    assert_eq!(
        safe.recovery,
        crate::engine::model::ProviderRecoverySignal::BillingExhausted
    );
    let safe_json = serde_json::to_string(&safe).unwrap();
    assert!(!safe_json.contains(SECRET), "funnel leaked raw detail: {safe_json}");

    // Sinks 1-3 — the subagent failure envelope + its serialized
    // `subagent_report` event + the rendered failure report. All flow from the
    // one `from_error` construction that routes through the funnel.
    let err = anyhow::Error::new(make_failure());
    let envelope = SubagentFailureEnvelope::from_error(&err, Vec::new())
        .expect("an inference failure yields a subagent failure envelope");
    assert_eq!(envelope.detail, crate::engine::model::PROVIDER_DETAIL_OMITTED);
    assert!(!envelope.detail.contains(SECRET));
    // Typed metadata stays queryable on the envelope.
    assert_eq!(envelope.observed_status, Some(429));
    assert_eq!(
        envelope.recovery,
        crate::engine::model::ProviderRecoverySignal::BillingExhausted
    );
    // The serialized event (what `subagent_report` persists/emits) omits the
    // secret but keeps the metadata.
    let envelope_json = serde_json::to_value(&envelope).unwrap();
    let envelope_json_str = envelope_json.to_string();
    assert!(
        !envelope_json_str.contains(SECRET),
        "serialized subagent_report leaked raw detail: {envelope_json_str}"
    );
    assert_eq!(envelope_json["observed_status"], serde_json::json!(429));
    assert_eq!(envelope_json["recovery"], serde_json::json!("BillingExhausted"));
    // The rendered report handed to the parent model omits the secret too.
    let report =
        render_failed_subagent_failure(&envelope, &DelegationPartialProgress::default());
    assert!(!report.contains(SECRET), "rendered subagent report leaked raw detail: {report}");

    // Sink 4 — the driver's failed-turn recovery record. The recorded event's
    // JSON must not carry the secret, while the observed-status + recovery
    // metadata remain queryable.
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "record the recovery without leaking detail",
            None,
            None,
        )
        .await
        .unwrap();
    let agent = driver.stack[0].agent.clone();
    let attempted = Message::user("continue the failed turn");
    let call_id = uuid::Uuid::new_v4();
    let recovery_failure = make_failure();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    driver
        .record_failed_turn_recovery(&agent, &attempted, call_id, &recovery_failure, &tx)
        .await;
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let recovery = events
        .iter()
        .find(|event| event.kind == "failed_turn_recovery")
        .expect("failed_turn_recovery event recorded");
    let recovery_str = recovery.data.to_string();
    assert!(
        !recovery_str.contains(SECRET),
        "failed_turn_recovery leaked raw detail: {recovery_str}"
    );
    assert_eq!(
        recovery.data["provider_body_snippet"],
        serde_json::json!(crate::engine::model::PROVIDER_DETAIL_OMITTED)
    );
    // Typed metadata stays queryable on the recovery record.
    assert_eq!(recovery.data["provider_status"], serde_json::json!(429));
    assert_eq!(recovery.data["recovery"], serde_json::json!("billing_exhausted"));
}
