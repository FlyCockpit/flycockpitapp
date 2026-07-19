use super::*;

#[test]
fn interactive_child_load_failure_returns_tool_error_without_pushing_child() {
    let (driver, tmp) = test_driver(8);
    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{"tools":{"read":{"enabled":true,"command":"echo hi"}}}"#,
    )
    .unwrap();

    let message = match driver.load_interactive_child_or_tool_error(InteractiveChildLoadRequest {
        child_agent: "builder",
        granted_tools: Vec::new(),
        model: None,
        child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        task_call_id: "task-load-fail",
        task_function_call_id: Some("fn-load-fail".to_string()),
        repair_notes: &[],
    }) {
        Ok(_) => panic!("invalid child config must return a tool error"),
        Err(message) => message,
    };

    assert_eq!(driver.stack.len(), 1, "parent session must remain alive");
    let (result_id, result_text) =
        tool_result_text_and_id(&message).expect("load failure returns tool_result");
    assert_eq!(result_id, "task-load-fail");
    assert!(
        result_text.contains("failed to load subagent `builder`"),
        "{result_text}"
    );
    assert!(result_text.contains("custom tool `read`"), "{result_text}");
}

#[tokio::test]
async fn unwind_stack_to_root_cancel_delivers_abort_result() {
    assert_unwind_reason(StackUnwindReason::Cancelled, "cancelled by user").await;
}

#[tokio::test]
async fn unwind_stack_to_root_gate_delivers_abort_result() {
    assert_unwind_reason(StackUnwindReason::Gated, "daemon draining").await;
}

#[tokio::test]
async fn unwind_stack_to_root_inference_failure_delivers_diagnostics() {
    assert_unwind_reason(
        StackUnwindReason::InferenceFailed {
            provider: "lmstudio".into(),
            model: "local".into(),
            class: "timeout_ttft".into(),
            phase: "ttft".into(),
        },
        "provider=lmstudio, model=local, class=timeout_ttft, phase=ttft",
    )
    .await;
}

#[tokio::test]
async fn root_only_unwind_emits_no_report() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .unwind_stack_to_root(StackUnwindReason::Cancelled, &tx)
        .await;

    assert_eq!(driver.stack.len(), 1);
    assert!(driver.stack[0].history.is_empty());
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn all_unwind_paths_drain_pending_input() {
    for reason in [
        StackUnwindReason::Cancelled,
        StackUnwindReason::Gated,
        StackUnwindReason::InferenceFailed {
            provider: "lmstudio".into(),
            model: "local".into(),
            class: "network".into(),
            phase: "dispatch".into(),
        },
    ] {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
        let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
        let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
        let target = driver.active_queue_target();
        for text in ["first", "second"] {
            queue
                .push(
                    UserSubmission {
                        kind: UserSubmissionKind::User,
                        text: text.to_string(),
                        display_text: None,
                        tag_expansions: Vec::new(),
                        images: vec![],
                        forced_skill: None,
                        origin_principal: None,
                        job_id: None,
                        preflight_cleaned: None,
                        queue_item_ids: Vec::new(),
                        queue_target: None,
                    },
                    target.clone(),
                )
                .await;
        }

        assert_eq!(
            driver
                .unwind_stack_to_root_and_discard_pending_input(reason, &queue, &tx)
                .await,
            2
        );
        let mut drained = Vec::new();
        queue
            .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
            .await;
        assert!(drained.is_empty());
    }
}

#[tokio::test]
async fn queued_user_fold_records_and_emits_stable_ids() {
    let (driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let target = driver.active_queue_target();
    let (first_id, _) = queue
        .push(UserSubmission::text("first queued"), target.clone())
        .await;
    let (second_id, _) = queue
        .push(UserSubmission::text("second queued"), target.clone())
        .await;

    let mut drained = Vec::new();
    queue
        .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
        .await;
    assert_eq!(drained.len(), 2);
    let first_seq = driver
        .record_queued_user_fold(&drained[0], &tx)
        .await
        .expect("first queued message should persist");
    let second_seq = driver
        .record_queued_user_fold(&drained[1], &tx)
        .await
        .expect("second queued message should persist");

    for (expected_text, expected_id, expected_seq) in [
        ("first queued", first_id, first_seq),
        ("second queued", second_id, second_seq),
    ] {
        let event = rx.try_recv().expect("queued turn event");
        match event {
            TurnEvent::QueuedUserMessagesFolded {
                text,
                queue_item_ids,
                target: event_target,
                seq: event_seq,
                preflight_cleaned,
                ..
            } => {
                assert_eq!(text, expected_text);
                assert_eq!(queue_item_ids, vec![expected_id]);
                assert_eq!(event_target.id, target.id);
                assert_eq!(event_seq, Some(expected_seq));
                assert!(preflight_cleaned.is_none());
            }
            other => panic!("expected queued turn event, got {other:?}"),
        }
    }

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    for (expected_text, expected_id, expected_seq) in [
        ("first queued", first_id, first_seq),
        ("second queued", second_id, second_seq),
    ] {
        let recorded = events
            .iter()
            .find(|event| event.seq == expected_seq)
            .expect("queued user_message event");
        assert_eq!(recorded.kind, "user_message");
        assert_eq!(recorded.data["text"], expected_text);
        assert_eq!(recorded.data["queued"], true);
        assert_eq!(recorded.data["queue_item_ids"][0], expected_id.to_string());
        assert_eq!(recorded.data["queue_target"]["id"], target.id);
    }
}
