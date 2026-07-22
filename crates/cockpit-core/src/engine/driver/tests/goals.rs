use super::*;

#[test]
fn goal_read_only_turns_count_as_no_progress_after_bound() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship without looping on reads",
            None,
            None,
        )
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq();

    record_goal_tool_event(&driver, "read", serde_json::json!({"path": "src/lib.rs"}));
    let first = driver.observe_goal_progress_turn().unwrap();
    assert!(first.no_progress());
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 1);

    record_goal_tool_event(
        &driver,
        "grep",
        serde_json::json!({"pattern": "TODO", "path": "src"}),
    );
    let second = driver.observe_goal_progress_turn().unwrap();

    assert!(second.no_progress());
    assert_eq!(
        driver.goal_turns_since_mutating_action,
        GOAL_NO_PROGRESS_NUDGE_BOUND
    );
    assert!(
        driver.goal_turns_since_goal_context_delta >= GOAL_NO_PROGRESS_NUDGE_BOUND,
        "read/search-only turns should cross the nudge bound"
    );
    assert_eq!(driver.goal_stall_prompt(), GOAL_IDLE_CONTINUATION);
}

#[test]
fn goal_mutating_action_and_context_delta_reset_progress_counters() {
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
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq();
    driver.goal_turns_since_mutating_action = 4;
    driver.goal_turns_since_goal_context_delta = 4;

    record_goal_tool_event(
        &driver,
        "writeunlock",
        serde_json::json!({"path": "src/lib.rs", "content": "changed"}),
    );
    let mutating = driver.observe_goal_progress_turn().unwrap();
    assert!(mutating.mutating_action);
    assert_eq!(driver.goal_turns_since_mutating_action, 0);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 5);

    record_goal_tool_event(
        &driver,
        "update_goal",
        serde_json::json!({"status": "active", "context_delta": "edited src/lib.rs"}),
    );
    let context = driver.observe_goal_progress_turn().unwrap();
    assert!(context.context_delta);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 0);
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
}

#[test]
fn goal_prose_without_tools_counts_as_no_progress_subset() {
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
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq();
    driver
        .stack
        .first_mut()
        .unwrap()
        .history
        .push(Message::assistant("I will keep working."));

    let observation = driver.observe_goal_progress_turn().unwrap();

    assert!(observation.no_progress());
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 1);
}

#[tokio::test]
async fn goal_no_progress_intervention_waits_for_budget_cap() {
    let (mut driver, tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "do not stop at three strikes",
            None,
            None,
        )
        .unwrap();
    driver.goal_no_tool_idle_count = 5;
    driver.goal_turns_since_mutating_action = GOAL_NO_PROGRESS_NUDGE_BOUND;
    driver.goal_turns_since_goal_context_delta = GOAL_NO_PROGRESS_NUDGE_BOUND;
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert!(
        !driver.goal_continuation_budget_exhausted(&goal),
        "fixed strike count must not be the terminating condition"
    );
    assert_eq!(driver.goal_stall_prompt(), GOAL_IDLE_CONTINUATION_STRONGEST);
    assert!(!driver.goal_idle_intervention_pending);

    driver
        .session
        .db
        .insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
            call_id: uuid::Uuid::new_v4(),
            session_id: driver.session.id,
            project_id: driver.session.project_id.clone(),
            project_root: tmp.path().display().to_string(),
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            input_tokens: GOAL_DEFAULT_CONTINUATION_TOKEN_CAP,
            output_tokens: 0,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility: false,
        })
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
        .unwrap();
    let capped = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .emit_goal_no_progress_budget_exhausted(&capped, &tx)
        .await;

    assert!(driver.goal_idle_intervention_pending);
    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::NeedsIntervention {
            code: "agent_failed_to_progress_budget_exhausted".to_string()
        }
    );
    match rx
        .try_recv()
        .expect("budget intervention notice should emit")
    {
        TurnEvent::Notice { text } => {
            assert!(text.contains("agent_failed_to_progress_budget_exhausted"));
        }
        other => panic!("expected intervention Notice, got {other:?}"),
    }
}

#[tokio::test]
async fn goal_budget_autopause_idle_reason_is_budget_limited() {
    let (mut driver, tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stay within budget",
            None,
            Some(1),
        )
        .unwrap();
    driver
        .session
        .db
        .insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
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
        })
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
        .unwrap();
    let (queue_updates_tx, _queue_updates_rx) = tokio::sync::watch::channel(Vec::new());
    let input_queue = crate::engine::message::UserSubmissionQueue::new(queue_updates_tx);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .maybe_continue_active_goal(&input_queue, &tx)
        .await
        .unwrap();

    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::BudgetLimited
    );
}

#[tokio::test]
async fn stalled_goal_token_budget_exhaustion_needs_intervention() {
    let (mut driver, tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stop stalled work at explicit budget",
            None,
            Some(10),
        )
        .unwrap();
    driver.goal_turns_since_mutating_action = GOAL_NO_PROGRESS_NUDGE_BOUND;
    driver.goal_turns_since_goal_context_delta = GOAL_NO_PROGRESS_NUDGE_BOUND;
    driver
        .session
        .db
        .insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
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
        })
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
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
        driver.take_idle_reason(),
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
        .unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let failure = crate::engine::model::InferenceFailure {
        provider: "test-provider".to_string(),
        model: "test-model".to_string(),
        phase: "stream".to_string(),
        class: "http_429".to_string(),
        elapsed_ms: 42,
        retry_attempts: 1,
        detail: "rate limited".to_string(),
    };

    assert!(driver.handle_goal_usage_limit_failure(&failure, &tx).await);

    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.status,
        crate::db::session_goals::GoalStatus::UsageLimited
    );
    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::UsageLimited
    );
    let mut watchdog = None;
    driver.refresh_goal_watchdog(&mut watchdog);
    assert!(watchdog.is_some(), "usage_limited goal should arm backoff");
    match rx.try_recv().expect("usage-limit notice should emit") {
        TurnEvent::Notice { text } => {
            assert!(text.contains("auto-resuming after backoff"), "{text}");
        }
        other => panic!("expected usage-limit Notice, got {other:?}"),
    }
}

#[test]
fn goal_usage_limit_watchdog_auto_resumes_to_active() {
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
        .unwrap();
    driver
        .session
        .db
        .update_session_goal(
            driver.session.id,
            crate::db::session_goals::GoalStatus::UsageLimited,
            None,
            None,
            Some("provider usage or rate limit reached"),
        )
        .unwrap();

    let action = driver.goal_usage_limit_watchdog_action().unwrap();

    assert_eq!(action, GoalUsageLimitWatchdogAction::AutoResume);
    assert_eq!(driver.goal_usage_limit_auto_resume_attempts, 1);
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert_eq!(goal.status, crate::db::session_goals::GoalStatus::Active);
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
        .unwrap();
    driver.goal_usage_limit_auto_resume_attempts = GOAL_USAGE_LIMIT_MAX_AUTO_RESUME_ATTEMPTS;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let failure = crate::engine::model::InferenceFailure {
        provider: "test-provider".to_string(),
        model: "test-model".to_string(),
        phase: "dispatch".to_string(),
        class: "rate_limit_exceeded".to_string(),
        elapsed_ms: 7,
        retry_attempts: 1,
        detail: "quota exhausted".to_string(),
    };

    assert!(driver.handle_goal_usage_limit_failure(&failure, &tx).await);

    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.status,
        crate::db::session_goals::GoalStatus::UsageLimited
    );
    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::NeedsIntervention {
            code: GOAL_USAGE_LIMIT_INTERVENTION_CODE.to_string()
        }
    );
    let mut watchdog = None;
    driver.refresh_goal_watchdog(&mut watchdog);
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

#[test]
fn ordinary_non_goal_idle_reason_is_completed() {
    let (mut driver, _tmp) = test_driver(1);

    assert_eq!(
        driver.take_idle_reason(),
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
        .unwrap();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();

    driver
        .emit_goal_no_progress_budget_exhausted(&goal, &tx)
        .await;

    assert_eq!(
        driver.take_idle_reason(),
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
        .unwrap();
    driver.goal_idle_intervention_pending = true;
    let anchor = driver.latest_session_event_seq();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "continue"}),
        )
        .unwrap();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::SkillAutoSelect,
            Some("Build"),
            None,
            &serde_json::json!({"rejections": []}),
        )
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
        .unwrap();

    assert!(
        !driver.goal_continue_progress_since(anchor),
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
        .unwrap();
    let diagnostic = events
        .iter()
        .find(|event| event.kind == "goal_progress_diagnostic")
        .expect("goal progress diagnostic is durable");
    assert_eq!(diagnostic.data["kind"], "goal_continue_no_progress");
    assert_eq!(diagnostic.data["anchor_seq"], serde_json::json!(anchor));
}

#[tokio::test]
async fn goal_continue_progress_accepts_goal_status_update() {
    let (driver, _tmp) = test_driver(1);
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
        .unwrap();
    let anchor = driver.latest_session_event_seq();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "continue"}),
        )
        .unwrap();
    driver
        .session
        .db
        .current_session_goal(driver.session.id, true)
        .unwrap();
    driver
        .session
        .db
        .update_session_goal(
            driver.session.id,
            crate::db::session_goals::GoalStatus::Complete,
            Some("done"),
            None,
            None,
        )
        .unwrap();

    assert!(
        driver.goal_continue_progress_since(anchor),
        "terminal goal status is progress even if no further tool is needed"
    );
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
        class: "network".into(),
        elapsed_ms: 42_000,
        retry_attempts: 1,
        detail: "HTTP 503 Service Unavailable".into(),
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
        .unwrap();

    let (id, prompt) = driver
        .failed_turn_retry_prompt_for("continue")
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
        driver.failed_turn_retry_prompt_for("continue").is_none(),
        "retry_started should prevent stale repeated continue"
    );
}
