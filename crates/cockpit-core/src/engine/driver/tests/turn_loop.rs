use super::*;

// Full-loop tests use the built-in read tool against each test's tempdir:
// it is approval-free, local, and still exercises native tool dispatch.

fn event_harness() -> (
    crate::engine::message::UserSubmissionQueue,
    mpsc::Sender<TurnEvent>,
    mpsc::Receiver<TurnEvent>,
) {
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (turn_tx, turn_rx) = mpsc::channel(64);
    (queue, turn_tx, turn_rx)
}

fn drain_events(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

fn scripted_driver(provider: &ScriptedProvider) -> (Driver, tempfile::TempDir) {
    let (driver, tmp) = test_driver_with_url(8, provider.base_url());
    driver
        .session
        .set_active_model("lmstudio", "local")
        .unwrap();
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("lmstudio")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("local"));
    (driver, tmp)
}

fn scripted_read_driver(provider: &ScriptedProvider) -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = scripted_driver(provider);
    let old = driver.stack[0].agent.clone();
    let tools = crate::engine::tool::ToolBox::new().with(Arc::new(crate::tools::read::ReadTool));
    driver.stack[0].agent = Arc::new(Agent {
        name: old.name.clone(),
        system: old.system.clone(),
        role_prompt: old.role_prompt.clone(),
        tools,
        model: old.model.clone(),
        params: old.params.clone(),
        scan_tool_results: old.scan_tool_results,
        llm_mode: old.llm_mode,
        lock_identity: "Build".to_string(),
        write_scope: None,
        delegated: old.delegated,
        delegation_recursion: old.delegation_recursion.clone(),
        env_overlay: old.env_overlay.clone(),
        assistant_identity_prefix: None,
    });
    (driver, tmp)
}

fn assistant_texts(events: &[TurnEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|event| match event {
            TurnEvent::AssistantText { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn tool_results(events: &[TurnEvent]) -> Vec<(&str, &str, &str)> {
    events
        .iter()
        .filter_map(|event| match event {
            TurnEvent::ToolEnd {
                call_id,
                tool,
                output,
                ..
            } => Some((call_id.as_str(), tool.as_str(), output.as_str())),
            _ => None,
        })
        .collect()
}

async fn session_events(driver: &Driver) -> Vec<crate::db::session_log::SessionEventRow> {
    driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap()
}

fn chat_messages(
    request: &cockpit_test_support::provider::CapturedRequest,
) -> &[serde_json::Value] {
    request.body["messages"]
        .as_array()
        .expect("chat completions messages")
}

fn provider_posts(
    provider: &ScriptedProvider,
) -> Vec<cockpit_test_support::provider::CapturedRequest> {
    provider
        .captured()
        .into_iter()
        .filter(|request| request.request_line.starts_with("POST "))
        .collect()
}

fn message_role(message: &serde_json::Value) -> &str {
    message["role"].as_str().expect("message role")
}

fn message_content_text(message: &serde_json::Value) -> String {
    match &message["content"] {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join(""),
        other => panic!("unexpected message content shape: {other:?}"),
    }
}

fn rich_client_submission(
    text: &str,
) -> (
    uuid::Uuid,
    UserSubmission,
    crate::engine::message::ClientSubmissionReceipt,
) {
    let id = uuid::Uuid::new_v4();
    let mut submission = UserSubmission {
        text: text.into(),
        display_text: Some(format!("display::{text}")),
        tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
            tool: "read".into(),
            path: "src/exact.rs".into(),
            detail: "73 lines".into(),
            ok: true,
        }],
        images: vec![vec![9, 8, 7, 6]],
        forced_skill: Some("review".into()),
        origin_principal: Some("flycockpit:exact-user".into()),
        job_id: Some("job-exact-retry".into()),
        ..Default::default()
    };
    let receipt = crate::engine::message::ClientSubmissionReceipt {
        id,
        fingerprint: submission.client_fingerprint(),
        wire_fingerprint: format!("wire::{text}"),
        origin_principal: submission.origin_principal.clone(),
    };
    submission.client_submissions.push(receipt.clone());
    (id, submission, receipt)
}

fn write_max_primary_rounds_config(root: &std::path::Path, max_verification_attempts: u32) {
    let cockpit = root.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "maxPrimaryRounds": max_verification_attempts
        }))
        .unwrap(),
    )
    .unwrap();
}

async fn inference_call_rows(driver: &Driver) -> Vec<(String, String, i64, i64, i64, i64, i64)> {
    let session_id = driver.session.id.to_string();
    driver
        .session
        .db
        .read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT provider, model, input_tokens, output_tokens, cached_input_tokens,
                        cache_creation_input_tokens, is_utility
                   FROM inference_calls
                  WHERE session_id = ?1
                  ORDER BY timestamp, call_id",
            )?;
            let rows = stmt.query_map([session_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
        .await
        .unwrap()
}

async fn inference_request_statuses(driver: &Driver) -> Vec<String> {
    let session_id = driver.session.id.to_string();
    driver
        .session
        .db
        .read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT status
                   FROM inference_requests
                  WHERE session_id = ?1
                  ORDER BY ts_ms, call_id",
            )?;
            let rows = stmt.query_map([session_id], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn turn_loop_text_only_turn_pushes_history_and_emits_events() {
    tokio::time::resume();
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("plain assistant reply".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let (queue, tx, mut rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("hello driver"), &queue, &tx)
        .await
        .unwrap();

    let events = drain_events(&mut rx);
    assert_eq!(provider_posts(&provider).len(), 1);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TurnEvent::UserMessageRecorded { .. })),
        "{events:?}"
    );
    assert_eq!(assistant_texts(&events), vec!["plain assistant reply"]);
    let thinking_index = events
        .iter()
        .position(|event| matches!(event, TurnEvent::ThinkingStarted { .. }))
        .expect("thinking event");
    let assistant_index = events
        .iter()
        .position(|event| matches!(event, TurnEvent::AssistantText { .. }))
        .expect("assistant event");
    assert!(
        thinking_index < assistant_index,
        "thinking must precede assistant output: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TurnEvent::InferenceSucceeded { provider, model } if provider == "lmstudio" && model == "local"))
    );
    assert!(
        matches!(events.last(), Some(TurnEvent::AssistantText { text, .. }) if text == "plain assistant reply"),
        "{events:?}"
    );
    assert!(
        driver.stack[0]
            .history
            .iter()
            .any(|message| matches!(message, Message::User { .. }))
    );
    assert_eq!(
        driver.stack[0]
            .history
            .iter()
            .filter(|message| matches!(message, Message::Assistant { .. }))
            .count(),
        1
    );
    assert!(history_text(&driver.stack[0].history).contains("plain assistant reply"));

    let events = session_events(&driver).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == "user_message")
            .count(),
        1
    );
    let assistant = events
        .iter()
        .find(|event| event.kind == "assistant_message")
        .expect("assistant_message event");
    assert_eq!(assistant.data["text"], "plain assistant reply");
}

#[tokio::test(start_paused = true)]
async fn client_submission_receipt_write_retries_before_the_only_inference() {
    tokio::time::resume();
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("durably accepted".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let (queue, tx, mut rx) = event_harness();
    let id = uuid::Uuid::new_v4();
    let mut submission = UserSubmission::text("keep the complete accepted payload");
    let fingerprint = submission.client_fingerprint();
    submission.queue_item_ids = vec![id];
    submission.client_submissions = vec![crate::engine::message::ClientSubmissionReceipt {
        id,
        fingerprint: fingerprint.clone(),
        wire_fingerprint: "wire-receipt".to_string(),
        origin_principal: None,
    }];
    driver.test_fail_next_user_message_event_write = true;

    driver
        .run_user_input(submission, &queue, &tx)
        .await
        .unwrap();

    let events = drain_events(&mut rx);
    assert_eq!(
        provider_posts(&provider).len(),
        1,
        "a transient receipt failure must never duplicate inference"
    );
    let recorded_index = events
        .iter()
        .position(|event| {
            matches!(
                event,
                TurnEvent::UserMessageRecorded {
                    client_submission_ids,
                    ..
                } if client_submission_ids == &[id]
            )
        })
        .expect("the retried event must become durable");
    let thinking_index = events
        .iter()
        .position(|event| matches!(event, TurnEvent::ThinkingStarted { .. }))
        .expect("provider inference started");
    assert!(recorded_index < thinking_index, "{events:?}");
    assert!(events.iter().any(|event| {
        matches!(event, TurnEvent::Notice { text } if text.contains("exact payload will be retried"))
    }));

    let durable = driver
        .session
        .db
        .client_submission_receipt(driver.session.id, id)
        .await
        .unwrap()
        .expect("restart dedupe must find the durable receipt");
    assert_eq!(durable.fingerprint, fingerprint);
    assert_eq!(durable.wire_fingerprint, "wire-receipt");
    assert_eq!(durable.origin_principal, None);
    assert_eq!(
        session_events(&driver)
            .await
            .iter()
            .filter(|event| event.kind == "user_message")
            .count(),
        1,
        "retry must persist one canonical user event"
    );
}

#[test]
fn persistent_user_event_failure_defers_exact_payload_and_services_controls() {
    crate::test_env::run_async_with_large_stack(|| async {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::Text("must not run".into()))
            .start()
            .await;
        let (mut driver, _tmp) = scripted_driver(&provider);
        driver.test_fail_all_user_message_event_writes = true;
        let (queue, tx, mut rx) = event_harness();
        let target = driver.active_queue_target();
        let id = uuid::Uuid::new_v4();
        let mut submission = UserSubmission {
            text: "exact wire payload".into(),
            display_text: Some("visible draft".into()),
            tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
                tool: "read".into(),
                path: "src/lib.rs".into(),
                detail: "42 lines".into(),
                ok: true,
            }],
            images: vec![vec![1, 2, 3, 4]],
            forced_skill: Some("review".into()),
            origin_principal: Some("flycockpit:user-1".into()),
            job_id: Some("job-exact".into()),
            ..Default::default()
        };
        let receipt = crate::engine::message::ClientSubmissionReceipt {
            id,
            fingerprint: submission.client_fingerprint(),
            wire_fingerprint: "wire-fingerprint".into(),
            origin_principal: submission.origin_principal.clone(),
        };
        submission.client_submissions.push(receipt.clone());
        let (_, _, outcome) = queue
            .push_idempotent(receipt, submission.clone(), target.clone())
            .await;
        assert_eq!(outcome, crate::engine::message::IdempotentPush::Inserted);

        let (control_tx, control_rx) = mpsc::channel(4);
        let run_queue = queue.clone();
        let run_tx = tx.clone();
        let run =
            tokio::spawn(async move { driver.run_main_loop(run_queue, control_rx, &run_tx).await });
        let notice = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(TurnEvent::Notice { text }) = rx.recv().await
                    && text.contains("exact payload will be retried")
                {
                    break text;
                }
            }
        })
        .await
        .expect("persistent failure emits a bounded retry notice");
        assert!(notice.contains("exact payload will be retried"), "{notice}");

        control_tx.send(DriverControl::AbortForTest).await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), run)
            .await
            .expect("a driver control is serviced while the payload is deferred")
            .expect("driver task joins");
        assert!(
            result
                .expect_err("test abort terminates the driver")
                .to_string()
                .contains("driver abort requested for test")
        );
        assert_eq!(provider_posts(&provider).len(), 0);

        let mut expected = submission;
        expected.queue_item_ids = vec![id];
        expected.queue_target = Some(target);
        let retried = tokio::time::timeout(std::time::Duration::from_secs(2), queue.recv())
            .await
            .expect("deferred payload becomes runnable")
            .expect("exact payload remains queued");
        assert_eq!(
            serde_json::to_value(retried).unwrap(),
            serde_json::to_value(expected).unwrap(),
            "every wire/display/tag/image/skill/origin field survives the retry"
        );
    });
}

#[tokio::test(start_paused = true)]
async fn preflight_terminal_write_retry_does_not_rerun_preflight() {
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("must not run".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    driver
        .session
        .db
        .write(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_preflight_terminal_receipt
                 BEFORE INSERT ON client_submission_terminal_receipts
                 BEGIN
                   SELECT RAISE(FAIL, 'persistent terminal receipt failure');
                 END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let (queue, tx, mut rx) = event_harness();
    let target = driver.active_queue_target();
    let id = uuid::Uuid::new_v4();
    let mut submission = UserSubmission::text("reject once only");
    let receipt = crate::engine::message::ClientSubmissionReceipt {
        id,
        fingerprint: submission.client_fingerprint(),
        wire_fingerprint: "reject-wire".into(),
        origin_principal: None,
    };
    submission.client_submissions.push(receipt.clone());
    queue.push_idempotent(receipt, submission, target).await;
    driver.test_reject_next_submission_preflight = true;

    let first = queue.recv().await.unwrap();
    assert!(
        driver
            .prepare_queued_user_submission(first, &queue, &tx)
            .await
            .is_none()
    );
    assert!(matches!(
        queue
            .pending_submission(id)
            .await
            .and_then(|submission| submission.pending_terminal_disposition),
        Some(crate::engine::message::PendingSubmissionTerminalDisposition::PreflightRejected)
    ));

    let second = queue.recv().await.unwrap();
    assert!(
        driver
            .prepare_queued_user_submission(second, &queue, &tx)
            .await
            .is_none(),
        "the retry must settle the prior rejection rather than rerun the one-shot preflight"
    );
    assert_eq!(provider_posts(&provider).len(), 0);

    driver
        .session
        .db
        .write(|conn| {
            conn.execute_batch("DROP TRIGGER fail_preflight_terminal_receipt;")?;
            Ok(())
        })
        .await
        .unwrap();
    let third = queue.recv().await.unwrap();
    assert!(
        driver
            .prepare_queued_user_submission(third, &queue, &tx)
            .await
            .is_none()
    );
    queue.finish(&[id]).await;
    let events = drain_events(&mut rx);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TurnEvent::UserMessageRetracted { .. }))
            .count(),
        1,
        "only the durable terminal transition retracts the accepted message"
    );
    assert!(queue.snapshot().await.is_empty());
    assert_eq!(provider_posts(&provider).len(), 0);
}

#[test]
fn later_batch_persist_failure_retains_recorded_history_and_recovers_fifo() {
    crate::test_env::run_async_with_large_stack(|| async {
        const LEADING: &str = "queue-leading-a-7f91";
        const RETRIED: &str = "queue-retry-b-8e02";
        const FINAL: &str = "queue-final-c-9d13";
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::Text("batch recovered".into()))
            .start()
            .await;
        let (mut driver, _tmp) = scripted_driver(&provider);
        driver
            .session
            .db
            .write(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER fail_second_batch_user_event
                 BEFORE INSERT ON session_events
                 WHEN NEW.type = 'user_message'
                   AND json_extract(NEW.data_json, '$.text') = 'queue-retry-b-8e02'
                 BEGIN
                   SELECT RAISE(FAIL, 'persistent B failure');
                 END;",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let (queue, tx, _rx) = event_harness();
        let target = driver.active_queue_target();
        for text in [LEADING, RETRIED, FINAL] {
            let id = uuid::Uuid::new_v4();
            let mut submission = UserSubmission::text(text);
            let receipt = crate::engine::message::ClientSubmissionReceipt {
                id,
                fingerprint: submission.client_fingerprint(),
                wire_fingerprint: format!("wire-{text}"),
                origin_principal: None,
            };
            submission.client_submissions.push(receipt.clone());
            queue
                .push_idempotent(receipt, submission, target.clone())
                .await;
        }
        let mut first_batch = Vec::new();
        queue
            .drain_into_for(&mut first_batch, 3, Some(&target.id))
            .await;
        driver
            .run_prepared_queued_user_batch(first_batch, &queue, &tx)
            .await
            .unwrap();

        assert_eq!(provider_posts(&provider).len(), 0);
        let after_failure = history_text(&driver.stack[0].history);
        assert_eq!(after_failure.matches(LEADING).count(), 1, "{after_failure}");
        assert_eq!(after_failure.matches(RETRIED).count(), 0, "{after_failure}");
        assert_eq!(after_failure.matches(FINAL).count(), 0, "{after_failure}");
        let durable_after_failure = session_events(&driver).await;
        assert_eq!(
            durable_after_failure
                .iter()
                .filter(|event| event.kind == "user_message" && event.data["text"] == LEADING)
                .count(),
            1
        );

        driver
            .session
            .db
            .write(|conn| {
                conn.execute_batch("DROP TRIGGER fail_second_batch_user_event;")?;
                Ok(())
            })
            .await
            .unwrap();
        let first_retried = queue.recv().await.unwrap();
        assert_eq!(first_retried.text, RETRIED);
        let mut recovered = vec![first_retried];
        queue
            .drain_into_for(&mut recovered, 3, Some(&target.id))
            .await;
        assert_eq!(
            recovered
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            [RETRIED, FINAL]
        );
        driver
            .run_prepared_queued_user_batch(recovered, &queue, &tx)
            .await
            .unwrap();

        let posts = provider_posts(&provider);
        assert_eq!(posts.len(), 1);
        let user_text = chat_messages(&posts[0])
            .iter()
            .filter(|message| message_role(message) == "user")
            .map(message_content_text)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(user_text.matches(LEADING).count(), 1, "{user_text}");
        assert_eq!(user_text.matches(RETRIED).count(), 1, "{user_text}");
        assert_eq!(user_text.matches(FINAL).count(), 1, "{user_text}");
        let a = user_text
            .find(LEADING)
            .expect("leading message remains in context");
        let b = user_text
            .find(RETRIED)
            .expect("failed message is retried next");
        let c = user_text.find(FINAL).expect("final message remains last");
        assert!(a < b && b < c, "{user_text}");
        let durable = session_events(&driver).await;
        for text in [LEADING, RETRIED, FINAL] {
            assert_eq!(
                durable
                    .iter()
                    .filter(|event| event.kind == "user_message" && event.data["text"] == text)
                    .count(),
                1,
                "{text} must have one canonical durable event"
            );
        }
        assert!(queue.snapshot().await.is_empty());
    });
}

#[test]
fn continue_fold_failure_restores_tool_result_and_defers_exact_payload() {
    crate::test_env::run_async_with_large_stack(|| async {
        const QUEUED: &str = "continue-queued-exact-4bb2";
        let mut provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: "continue-read".into(),
                name: "read".into(),
                arguments: serde_json::json!({ "path": "continue.txt" }),
            })
            .with_delay(std::time::Duration::from_millis(500))
            .turn(Turn::Text("initial turn complete".into()))
            .turn(Turn::Text("queued turn recovered".into()))
            .start()
            .await;
        let (mut driver, tmp) = scripted_read_driver(&provider);
        std::fs::write(tmp.path().join("continue.txt"), "continue-fixture-body").unwrap();
        driver.test_fail_all_user_message_event_writes = true;
        let (queue, tx, _rx) = event_harness();
        let target = driver.active_queue_target();
        let (id, submission, receipt) = rich_client_submission(QUEUED);
        let expected = submission.clone();

        let run = driver.run_user_input(UserSubmission::text("start continue path"), &queue, &tx);
        let enqueue = async {
            let _ = provider.next_request().await;
            let (_, _, outcome) = queue
                .push_idempotent(receipt, submission, target.clone())
                .await;
            assert_eq!(outcome, crate::engine::message::IdempotentPush::Inserted);
        };
        let (result, ()) = tokio::join!(run, enqueue);
        result.unwrap();

        let posts = provider_posts(&provider);
        assert_eq!(
            posts.len(),
            2,
            "the failed queued fold must not start inference"
        );
        assert!(
            !serde_json::to_string(&posts[1].body)
                .unwrap()
                .contains(QUEUED),
            "the Continue retry must carry only the prior tool result"
        );
        let history = history_text(&driver.stack[0].history);
        assert_eq!(
            history.matches("continue-fixture-body").count(),
            1,
            "{history}"
        );
        assert_eq!(history.matches(QUEUED).count(), 0, "{history}");
        assert!(
            driver
                .session
                .db
                .client_submission_receipt(driver.session.id, id)
                .await
                .unwrap()
                .is_none(),
            "the failed receipt must not be falsely marked finished"
        );

        let retried = queue.recv().await.unwrap();
        let mut expected = expected;
        expected.queue_item_ids = vec![id];
        expected.queue_target = Some(target);
        assert_eq!(
            serde_json::to_value(&retried).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        driver.test_fail_all_user_message_event_writes = false;
        driver.run_user_input(retried, &queue, &tx).await.unwrap();
        let posts = provider_posts(&provider);
        assert_eq!(posts.len(), 3);
        assert!(
            serde_json::to_string(&posts[2].body)
                .unwrap()
                .contains(QUEUED)
        );
        assert!(
            driver
                .session
                .db
                .client_submission_receipt(driver.session.id, id)
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn done_fold_failure_defers_exact_payload_without_second_inference() {
    crate::test_env::run_async_with_large_stack(|| async {
        const QUEUED: &str = "done-queued-exact-6cc4";
        let mut provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::Text("initial done".into()))
            .with_delay(std::time::Duration::from_millis(500))
            .turn(Turn::Text("queued done recovered".into()))
            .start()
            .await;
        let (mut driver, _tmp) = scripted_driver(&provider);
        driver.test_fail_all_user_message_event_writes = true;
        let (queue, tx, _rx) = event_harness();
        let target = driver.active_queue_target();
        let (id, submission, receipt) = rich_client_submission(QUEUED);
        let expected = submission.clone();

        let run = driver.run_user_input(UserSubmission::text("start done path"), &queue, &tx);
        let enqueue = async {
            let _ = provider.next_request().await;
            let (_, _, outcome) = queue
                .push_idempotent(receipt, submission, target.clone())
                .await;
            assert_eq!(outcome, crate::engine::message::IdempotentPush::Inserted);
        };
        let (result, ()) = tokio::join!(run, enqueue);
        result.unwrap();

        let posts = provider_posts(&provider);
        assert_eq!(
            posts.len(),
            1,
            "Done must return instead of inferring failed input"
        );
        assert!(
            !serde_json::to_string(&posts[0].body)
                .unwrap()
                .contains(QUEUED)
        );
        assert_eq!(
            history_text(&driver.stack[0].history)
                .matches(QUEUED)
                .count(),
            0
        );
        assert!(
            driver
                .session
                .db
                .client_submission_receipt(driver.session.id, id)
                .await
                .unwrap()
                .is_none()
        );

        let retried = queue.recv().await.unwrap();
        let mut expected = expected;
        expected.queue_item_ids = vec![id];
        expected.queue_target = Some(target);
        assert_eq!(
            serde_json::to_value(&retried).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        driver.test_fail_all_user_message_event_writes = false;
        driver.run_user_input(retried, &queue, &tx).await.unwrap();
        let posts = provider_posts(&provider);
        assert_eq!(posts.len(), 2);
        assert!(
            serde_json::to_string(&posts[1].body)
                .unwrap()
                .contains(QUEUED)
        );
        assert!(
            driver
                .session
                .db
                .client_submission_receipt(driver.session.id, id)
                .await
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn turn_loop_tool_call_result_feeds_second_inference() {
    crate::test_env::run_async_with_large_stack(|| async {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: "read-fixture".into(),
                name: "read".into(),
                arguments: serde_json::json!({ "path": "fixture.txt" }),
            })
            .turn(Turn::Text("I read the file.".into()))
            .start()
            .await;
        let (mut driver, tmp) = scripted_read_driver(&provider);
        std::fs::write(tmp.path().join("fixture.txt"), "fixture body").unwrap();
        let (queue, tx, mut rx) = event_harness();

        driver
            .run_user_input(UserSubmission::text("read fixture"), &queue, &tx)
            .await
            .unwrap();

        let events = drain_events(&mut rx);
        assert_eq!(tool_results(&events).len(), 1);
        assert_eq!(tool_results(&events)[0].0, "read-fixture");
        assert_eq!(tool_results(&events)[0].1, "read");
        assert!(tool_results(&events)[0].2.contains("fixture body"));
        assert_eq!(assistant_texts(&events), vec!["I read the file."]);
        assert_eq!(provider.captured().len(), 2);

        let captured = provider.captured();
        let second_messages = chat_messages(&captured[1]);
        let [.., assistant_call, result] = second_messages else {
            panic!(
                "second request should end with assistant tool call and tool result: {second_messages:?}"
            );
        };
        assert_eq!(message_role(assistant_call), "assistant");
        assert_eq!(assistant_call["tool_calls"][0]["function"]["name"], "read");
        assert_eq!(assistant_call["tool_calls"][0]["id"], "read-fixture");
        assert_eq!(message_role(result), "tool");
        assert_eq!(result["tool_call_id"], "read-fixture");
        assert!(message_content_text(result).contains("fixture body"));
    });
}

#[test]
fn turn_loop_parallel_tool_calls_preserve_order_and_call_id_pairing() {
    crate::test_env::run_async_with_large_stack(|| async {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ParallelToolCalls(vec![
                (
                    "read-alpha".into(),
                    "read".into(),
                    serde_json::json!({ "path": "alpha.txt" }),
                ),
                (
                    "read-beta".into(),
                    "read".into(),
                    serde_json::json!({ "path": "beta.txt" }),
                ),
            ]))
            .turn(Turn::Text("Both files were read.".into()))
            .start()
            .await;
        let (mut driver, tmp) = scripted_read_driver(&provider);
        std::fs::write(tmp.path().join("alpha.txt"), "alpha body").unwrap();
        std::fs::write(tmp.path().join("beta.txt"), "beta body").unwrap();
        let (queue, tx, mut rx) = event_harness();

        driver
            .run_user_input(UserSubmission::text("read both"), &queue, &tx)
            .await
            .unwrap();

        let events = drain_events(&mut rx);
        let results = tool_results(&events);
        assert_eq!(
            results.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(),
            vec!["read-alpha", "read-beta"]
        );
        assert!(results[0].2.contains("alpha body"));
        assert!(results[1].2.contains("beta body"));

        let captured = provider.captured();
        let second_messages = chat_messages(&captured[1]);
        let result_ids = second_messages
            .iter()
            .filter(|message| message_role(message) == "tool")
            .map(|message| message["tool_call_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(result_ids, vec!["read-alpha", "read-beta"]);
    });
}

#[test]
fn turn_loop_tool_error_becomes_tool_result_not_turn_abort() {
    crate::test_env::run_async_with_large_stack(|| async {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: "read-missing".into(),
                name: "read".into(),
                arguments: serde_json::json!({ "path": "missing.txt" }),
            })
            .turn(Turn::Text("I handled the missing file.".into()))
            .start()
            .await;
        let (mut driver, _tmp) = scripted_read_driver(&provider);
        let (queue, tx, mut rx) = event_harness();

        driver
            .run_user_input(UserSubmission::text("read missing"), &queue, &tx)
            .await
            .unwrap();

        let events = drain_events(&mut rx);
        let results = tool_results(&events);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "read-missing");
        assert_eq!(results[0].1, "read");
        assert!(results[0].2.contains("missing.txt"), "{}", results[0].2);
        assert_eq!(
            assistant_texts(&events),
            vec!["I handled the missing file."]
        );
        assert_eq!(provider.captured().len(), 2);

        let captured = provider.captured();
        let tool_result = chat_messages(&captured[1])
            .iter()
            .find(|message| message_role(message) == "tool")
            .expect("tool error returned to model");
        assert_eq!(tool_result["tool_call_id"], "read-missing");
        assert!(message_content_text(tool_result).contains("missing.txt"));
    });
}

#[test]
fn turn_loop_max_verification_attempts_guard_terminates_turn() {
    crate::test_env::run_async_with_large_stack(|| async {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: "read-one".into(),
                name: "read".into(),
                arguments: serde_json::json!({ "path": "one.txt" }),
            })
            .turn(Turn::Text("should not be requested".into()))
            .start()
            .await;
        let (mut driver, tmp) = scripted_read_driver(&provider);
        std::fs::write(tmp.path().join("one.txt"), "one body").unwrap();
        write_max_primary_rounds_config(tmp.path(), 1);
        driver.refresh_config_from_disk_for_tests();
        let (queue, tx, mut rx) = event_harness();

        driver
            .run_user_input(UserSubmission::text("read once"), &queue, &tx)
            .await
            .unwrap();

        let events = drain_events(&mut rx);
        assert_eq!(tool_results(&events).len(), 1);
        assert!(assistant_texts(&events).is_empty());
        assert!(
        events
            .iter()
            .any(|event| matches!(event, TurnEvent::Notice { text } if text.contains("configured limit of 1") && text.contains("no interactive client"))),
        "{events:?}"
    );
        assert_eq!(provider.captured().len(), 1);
    });
}

#[tokio::test]
async fn turn_loop_terminal_inference_failure_ends_turn_cleanly() {
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::HttpError {
            status: 500,
            body:
                r#"{"error":{"message":"server failed","type":"server_error","code":"server_error"}}"#
                    .into(),
        })
        .repeat_last()
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let (queue, tx, mut rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("fail once"), &queue, &tx)
        .await
        .unwrap();

    let events = drain_events(&mut rx);
    assert!(
        events.iter().any(|event| matches!(
            event,
            TurnEvent::InferenceFailed {
                provider,
                model,
                error_class: crate::engine::model::InferenceErrorClass::Http(500),
                ..
            } if provider == "lmstudio" && model == "local"
        )),
        "{events:?}"
    );
    assert!(assistant_texts(&events).is_empty());
    assert_eq!(driver.stack.len(), 1);
    assert_eq!(
        driver.stack[0]
            .history
            .iter()
            .filter(|message| matches!(message, Message::Assistant { .. }))
            .count(),
        0
    );

    let events = session_events(&driver).await;
    assert!(events.iter().any(|event| event.kind == "inference_failure"));
    assert!(
        events
            .iter()
            .any(|event| event.kind == "failed_turn_recovery")
    );
}

#[tokio::test]
async fn turn_loop_retry_then_success_lands_exactly_one_assistant_message() {
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .path_status_for("/v1/chat/completions", 503, 1)
        .turn(Turn::Text("retry recovered".into()))
        .repeat_last()
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let (queue, tx, mut rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("retry please"), &queue, &tx)
        .await
        .unwrap();

    let events = drain_events(&mut rx);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TurnEvent::Reconnecting { attempt: 1, provider, model, .. } if provider == "openai-compatible" && model == "local")),
        "{events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::InferenceFailed { .. }))
    );
    assert_eq!(assistant_texts(&events), vec!["retry recovered"]);
    assert_eq!(provider_posts(&provider).len(), 2);
    assert!(
        matches!(events.last(), Some(TurnEvent::AssistantText { text, .. }) if text == "retry recovered"),
        "{events:?}"
    );
    assert_eq!(
        driver.stack[0]
            .history
            .iter()
            .filter(|message| matches!(message, Message::Assistant { .. }))
            .count(),
        1
    );
    let events = session_events(&driver).await;
    let assistant_messages = events
        .iter()
        .filter(|event| event.kind == "assistant_message")
        .collect::<Vec<_>>();
    assert_eq!(assistant_messages.len(), 1);
    assert_eq!(assistant_messages[0].data["text"], "retry recovered");
}

#[tokio::test(start_paused = true)]
async fn turn_loop_cancellation_mid_stream_does_not_persist_partial_output() {
    let mut provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Hang)
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let cancel = driver.cancel_handle();
    let (queue, tx, mut rx) = event_harness();

    let handle = tokio::spawn(async move {
        driver
            .run_user_input(UserSubmission::text("hang then cancel"), &queue, &tx)
            .await
            .unwrap();
        driver
    });
    let _captured = provider.next_request().await;
    cancel.cancel();
    let driver = handle.await.unwrap();

    let events = drain_events(&mut rx);
    assert!(assistant_texts(&events).is_empty(), "{events:?}");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::InferenceFailed { .. }))
    );
    assert_eq!(driver.stack.len(), 1);
    assert_eq!(
        driver.stack[0]
            .history
            .iter()
            .filter(|message| matches!(message, Message::Assistant { .. }))
            .count(),
        0
    );
    let events = session_events(&driver).await;
    assert!(!events.iter().any(|event| event.kind == "assistant_message"));
    assert_eq!(inference_request_statuses(&driver).await, vec!["cancelled"]);
}

#[tokio::test]
async fn turn_loop_emits_usage_event_from_provider_reported_usage() {
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("usage recorded".into()))
        .with_usage(Usage {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 18,
            use_alias_names: false,
        })
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let (queue, tx, mut rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("report usage"), &queue, &tx)
        .await
        .unwrap();

    let events = drain_events(&mut rx);
    let usage_events = events
        .iter()
        .filter_map(|event| match event {
            TurnEvent::Usage { agent, usage } => Some((agent.as_str(), *usage)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(usage_events.len(), 1);
    assert_eq!(usage_events[0].0, "Build");
    assert_eq!(usage_events[0].1.input_tokens, 11);
    assert_eq!(usage_events[0].1.output_tokens, 7);

    let rows = inference_call_rows(&driver).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "lmstudio");
    assert_eq!(rows[0].1, "local");
    assert_eq!(rows[0].2, 11);
    assert_eq!(rows[0].3, 7);
    assert_eq!(rows[0].4, 0);
    assert_eq!(rows[0].5, 0);
    assert_eq!(rows[0].6, 0);
}

// ── Inference journal barrier (make-inference-journal-barrier-testable) ──

/// AC2: driving the real turn loop, the journal's durable `dispatching` commit
/// is authorized BEFORE any provider handoff. With the journal parked inside
/// `begin_dispatch`, the counting provider has received zero requests; only once
/// the commit is released does exactly one handoff occur. If the provider call
/// were reordered ahead of the journal commit, the parked observation would see
/// a non-zero request count and fail.
#[tokio::test]
async fn inference_journal_commit_precedes_provider_handoff() {
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("gated reply".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let journal = driver
        .session
        .external_journal()
        .expect("the test driver installs a production-shaped journal");
    let gate = journal.install_dispatch_gate();
    let (queue, tx, _rx) = event_harness();

    let run = driver.run_user_input(UserSubmission::text("hello"), &queue, &tx);
    let observe = async {
        gate.wait_until_reached().await;
        assert_eq!(
            provider.request_count(),
            0,
            "no provider handoff may happen before the journal authorizes it"
        );
        gate.release();
    };
    let (result, ()) = tokio::join!(run, observe);
    result.unwrap();

    assert_eq!(
        provider.request_count(),
        1,
        "exactly one provider call happens once the journal authorizes the handoff"
    );
}

/// AC4: when a session has no durable journal AND the primary audit-row write
/// fails, nothing records the inference, so the provider handoff is refused —
/// no "warn and continue". The control run proves the harness dispatches
/// normally (so the refusal's zero count is not vacuous).
#[tokio::test]
async fn dual_audit_failure_refuses_provider_handoff() {
    // Control: an unjournaled session whose primary audit row writes cleanly
    // still reaches the provider.
    {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::Text("control reply".into()))
            .start()
            .await;
        let (mut driver, _tmp) = scripted_driver(&provider);
        driver.session.set_external_journal(None);
        driver.session.allow_unjournaled_inference(
            crate::session::UnjournaledInferenceReason::CagedSelfReviewUtility,
        );
        let (queue, tx, _rx) = event_harness();
        let _ = driver
            .run_user_input(UserSubmission::text("hello"), &queue, &tx)
            .await;
        assert_eq!(
            provider.request_count(),
            1,
            "control: an unjournaled session with a good primary row reaches the provider"
        );
    }

    // Dual failure: no journal AND the primary audit write fails ⇒ zero handoff.
    {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::Text("must-not-send".into()))
            .start()
            .await;
        let (mut driver, _tmp) = scripted_driver(&provider);
        driver.session.set_external_journal(None);
        driver.session.allow_unjournaled_inference(
            crate::session::UnjournaledInferenceReason::CagedSelfReviewUtility,
        );
        crate::session::journal_fault::set_fail_primary_inference_insert(true);
        let (queue, tx, _rx) = event_harness();
        let _ = driver
            .run_user_input(UserSubmission::text("hello"), &queue, &tx)
            .await;
        crate::session::journal_fault::set_fail_primary_inference_insert(false);
        assert_eq!(
            provider.request_count(),
            0,
            "dual failure (no journal + failed primary write) must refuse the handoff"
        );
    }
}
