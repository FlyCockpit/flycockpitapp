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

struct AllowOversizedTextArtifactJoin;

impl crate::db::db::message_attachments::MessageAcceptanceJoin for AllowOversizedTextArtifactJoin {
    fn validate_and_join(
        &self,
        _: &rusqlite::Connection,
        _: &crate::db::db::message_attachments::AcceptMessageInput,
    ) -> anyhow::Result<()> {
        Ok(())
    }
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

fn scripted_write_edit_driver(provider: &ScriptedProvider) -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = scripted_driver(provider);
    let old = driver.stack[0].agent.clone();
    let tools = crate::engine::tool::ToolBox::new()
        .with(Arc::new(crate::tools::write::WriteTool))
        .with(Arc::new(crate::tools::edit::EditTool));
    driver.stack[0].agent = Arc::new(Agent {
        name: old.name.clone(),
        system: old.system.clone(),
        role_prompt: old.role_prompt.clone(),
        tools,
        model: old.model.clone(),
        params: old.params.clone(),
        scan_tool_results: old.scan_tool_results,
        tool_steering: old.tool_steering,
        posture: old.posture.clone(),
        context_policy: None,
        lock_identity: "Build".to_string(),
        write_scope: None,
        workspace_lease: None,
        delegated: old.delegated,
        delegation_recursion: old.delegation_recursion.clone(),
        vnext_grant: old.vnext_grant.clone(),
        env_overlay: old.env_overlay.clone(),
        definition: old.definition.clone(),
        assistant_identity_prefix: None,
        mcp_resolver: old.mcp_resolver.clone(),
    });
    (driver, tmp)
}

fn long_write_content() -> String {
    let mut s = String::new();
    while crate::tokens::count(&s) < 140 {
        s.push_str(
            "fn example() { let value = expensive_computation(); println!(\"{value}\"); }\n",
        );
    }
    s.push_str("UNIQUE_NEEDLE_TO_REPLACE\n");
    s
}

fn tool_call_arguments(message: &serde_json::Value) -> serde_json::Value {
    let args = &message["tool_calls"][0]["function"]["arguments"];
    match args {
        serde_json::Value::String(s) => {
            serde_json::from_str(s).unwrap_or_else(|_| serde_json::json!(s))
        }
        other => other.clone(),
    }
}

fn assistant_tool_call_messages(messages: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    messages
        .iter()
        .filter(|message| {
            message_role(message) == "assistant" && message.get("tool_calls").is_some()
        })
        .collect()
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
        tool_steering: old.tool_steering,
        posture: old.posture.clone(),
        context_policy: None,
        lock_identity: "Build".to_string(),
        write_scope: None,
        workspace_lease: None,
        delegated: old.delegated,
        delegation_recursion: old.delegation_recursion.clone(),
        vnext_grant: old.vnext_grant.clone(),
        env_overlay: old.env_overlay.clone(),
        definition: old.definition.clone(),
        assistant_identity_prefix: None,
        mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
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
            TurnEvent::ToolError {
                call_id,
                tool,
                error,
                ..
            } => Some((call_id.as_str(), tool.as_str(), error.as_str())),
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
        images: vec![crate::engine::message::SubmissionImage::png(vec![
            9, 8, 7, 6,
        ])],
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

#[tokio::test]
async fn terminalized_oversized_submission_without_a_lease_never_reaches_provider() {
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("must not run".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    let source = "x".repeat(65_537);
    let operation_id = uuid::Uuid::new_v4();
    let client_submission_id = uuid::Uuid::new_v4();
    let queue_item_id = uuid::Uuid::new_v4();
    let accepted = driver
        .session
        .db
        .accept_message_with_text_artifact_reservation(
            crate::db::db::message_attachments::AcceptMessageInput {
                session_id: driver.session.id,
                operation_id: *operation_id.as_bytes(),
                actor: crate::db::db::message_attachments::MessageActor::LocalOwner,
                request_hash: [11; 32],
                message_request_digest: [12; 32],
                attachment_set_digest: [13; 32],
                client_submission_id: *client_submission_id.as_bytes(),
                queue_item_id: *queue_item_id.as_bytes(),
                canonical_message: b"FCM2\x02".to_vec(),
                attachments: Vec::new(),
                outbox_sequence: 0,
                now_ms: 1_000,
                tool_media_subject_binding: None,
            },
            std::sync::Arc::new(AllowOversizedTextArtifactJoin),
            crate::db::db::text_artifacts::source_digest(&source),
            source.len(),
        )
        .await
        .unwrap();
    let reservation = match accepted {
        crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Reserved(reservation) => {
            reservation
        }
        other => panic!("expected accepted oversized reservation, got {other:?}"),
    };
    driver
        .session
        .db
        .reap_expired_text_artifact_reservations(reservation.expires_at)
        .await
        .unwrap();

    let mut submission = UserSubmission::text(source);
    submission.origin = crate::engine::message::SubmissionOrigin::ExternalRoot;
    submission
        .client_submissions
        .push(crate::engine::message::ClientSubmissionReceipt {
            id: client_submission_id,
            fingerprint: "terminalized-oversized-source".to_owned(),
            wire_fingerprint: "terminalized-oversized-wire".to_owned(),
            origin_principal: None,
        });
    submission.pending_terminal_disposition =
        Some(crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact);
    let (queue, tx, mut rx) = event_harness();
    driver
        .run_user_input(submission, &queue, &tx)
        .await
        .unwrap();

    assert_eq!(
        provider_posts(&provider).len(),
        0,
        "the terminal receipt, not the mutable source text, owns the no-provider branch"
    );
    assert!(
        drain_events(&mut rx).iter().any(|event| {
            matches!(event, TurnEvent::Notice { text }
                if text.contains("artifact_reservation_expired")
                    && text.contains("will not execute its source"))
        }),
        "the phase-two no-lease branch reports the durable terminal outcome"
    );
    assert!(
        session_events(&driver)
            .await
            .iter()
            .all(|event| event.kind != "user_message"),
        "a terminalized oversized source must not fall through to an inline user event"
    );
}

#[tokio::test]
async fn oversized_user_provider_projection_replaces_the_full_source_with_its_typed_frame() {
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("artifact-aware reply".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    // `tag_expansions` is UI metadata; the resolved tag/context bytes are
    // already folded into the model-bound submission text and must therefore
    // survive the accepted envelope around the authored artifact slot.
    let source = format!(
        "RESOLVED TAG CONTEXT: src/lib.rs\noversized provider source line\n{}",
        "oversized provider source line\n".repeat(3_000)
    );
    assert!(source.len() > 64 * 1024);
    let operation_id = uuid::Uuid::new_v4();
    let client_submission_id = uuid::Uuid::new_v4();
    let canonical = crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2 {
        session_id: driver.session.id,
        canonical_project_digest: [1; 32],
        model_config_generation: 0,
        canonical_model_digest: [2; 32],
        request: crate::proto_crate::send_user_message_v2::SendUserMessageV2 {
            client_submission_id,
            origin: crate::proto_crate::UserMessageOrigin::ExternalRoot,
            text: source.clone(),
            display_text: None,
            tag_expansions: Vec::new(),
            forced_skill: None,
            delivery_class_override: None,
            resolved_delivery_class: None,
            resolved_queue_target: None,
            attachments: Vec::new(),
        },
    }
    .encode()
    .unwrap();
    let accepted = driver
        .session
        .db
        .accept_message_with_text_artifact_reservation(
            crate::db::db::message_attachments::AcceptMessageInput {
                session_id: driver.session.id,
                operation_id: *operation_id.as_bytes(),
                actor: crate::db::db::message_attachments::MessageActor::LocalOwner,
                request_hash: [3; 32],
                message_request_digest: [4; 32],
                attachment_set_digest: [5; 32],
                client_submission_id: *client_submission_id.as_bytes(),
                queue_item_id: *client_submission_id.as_bytes(),
                canonical_message: canonical,
                attachments: Vec::new(),
                outbox_sequence: 0,
                now_ms: chrono::Utc::now().timestamp_millis(),
                tool_media_subject_binding: None,
            },
            std::sync::Arc::new(AllowOversizedTextArtifactJoin),
            crate::db::db::text_artifacts::source_digest(&source),
            source.len(),
        )
        .await
        .unwrap();
    assert!(matches!(
        accepted,
        crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Reserved(_)
    ));

    let mut submission = UserSubmission::text(source.clone());
    submission.origin = crate::engine::message::SubmissionOrigin::ExternalRoot;
    submission.tag_expansions = vec![crate::daemon::proto::TagExpansionMeta {
        tool: "read".to_owned(),
        path: "src/lib.rs".to_owned(),
        detail: "resolved context".to_owned(),
        ok: true,
    }];
    let fingerprint = submission.client_fingerprint();
    submission
        .client_submissions
        .push(crate::engine::message::ClientSubmissionReceipt {
            id: client_submission_id,
            fingerprint,
            wire_fingerprint: "fcm2-oversized-provider-projection".to_owned(),
            origin_principal: None,
        });
    submission.pending_terminal_disposition =
        Some(crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact);
    let (queue, tx, _rx) = event_harness();
    driver
        .run_user_input(submission, &queue, &tx)
        .await
        .unwrap();

    let posts = provider_posts(&provider);
    assert_eq!(posts.len(), 1);
    let model_user_text = chat_messages(&posts[0])
        .iter()
        .filter(|message| message_role(message) == "user")
        .map(message_content_text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(model_user_text.contains("<cockpit_artifact_v1 "));
    assert!(model_user_text.contains("RESOLVED TAG CONTEXT: src/lib.rs"));
    assert!(
        !model_user_text.contains(&source),
        "the full oversized source must never be appended after the durable frame"
    );
    let artifacts = driver
        .session
        .db
        .list_text_artifacts(driver.session.id)
        .await
        .unwrap();
    assert!(artifacts.iter().any(|artifact| {
        artifact.kind == crate::db::db::text_artifacts::TextArtifactKind::UserInputSource
            && artifact.content == source
    }));
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
            images: vec![crate::engine::message::SubmissionImage::png(vec![
                1, 2, 3, 4,
            ])],
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

/// Hold-gated ReadOnly ordinary tool used to observe FIFO lane admission.
/// Source-order result folding cannot prove `max_parallel`: the Driver inserts
/// lane results from a `BTreeMap<usize, _>` even when more than the bound run.
struct FifoLaneState {
    started: std::sync::Mutex<Vec<String>>,
    in_flight: std::sync::atomic::AtomicUsize,
    max_in_flight: std::sync::atomic::AtomicUsize,
    gates: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
}

impl FifoLaneState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: std::sync::Mutex::new(Vec::new()),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            max_in_flight: std::sync::atomic::AtomicUsize::new(0),
            gates: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn gate(&self, id: &str) -> Arc<tokio::sync::Notify> {
        self.gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone()
    }

    fn started(&self) -> Vec<String> {
        self.started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn release(&self, id: &str) {
        self.gate(id).notify_one();
    }
}

struct FifoLaneTool {
    state: Arc<FifoLaneState>,
}

#[async_trait::async_trait]
impl crate::engine::tool::Tool for FifoLaneTool {
    fn name(&self) -> &str {
        "fifo_lane"
    }

    fn description(&self) -> &str {
        "Hold-gated read-only fixture for FIFO max_parallel admission."
    }

    fn effect(&self) -> crate::engine::tool::ToolEffect {
        crate::engine::tool::ToolEffect::ReadOnly
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"]
        })
    }

    async fn call(
        &self,
        args: serde_json::Value,
        _ctx: &crate::engine::tool::ToolCtx,
    ) -> anyhow::Result<crate::engine::tool::ToolOutput> {
        let id = args
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing")
            .to_string();
        let gate = self.state.gate(&id);
        {
            self.state
                .started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(id.clone());
        }
        let n = self
            .state
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.state
            .max_in_flight
            .fetch_max(n, std::sync::atomic::Ordering::SeqCst);
        gate.notified().await;
        self.state
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::engine::tool::ToolOutput::text(format!("{id} body")))
    }
}

async fn wait_until_started(state: &FifoLaneState, count: usize) {
    for _ in 0..200 {
        if state.started().len() >= count {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!(
        "timed out waiting for {count} fifo_lane starts; observed {:?}",
        state.started()
    );
}

#[test]
fn large_write_elides_only_after_a_newer_assistant_turn_exists() {
    crate::test_env::run_async_with_large_stack(|| async {
        let content = long_write_content();
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: "write-large".into(),
                name: "write".into(),
                arguments: serde_json::json!({
                    "path": "big.rs",
                    "content": content
                }),
            })
            .turn(Turn::ToolCall {
                id: "edit-needle".into(),
                name: "edit".into(),
                arguments: serde_json::json!({
                    "path": "big.rs",
                    "old_string": "UNIQUE_NEEDLE_TO_REPLACE",
                    "new_string": "REPLACED_NEEDLE"
                }),
            })
            .turn(Turn::Text("wrote the file.".into()))
            .start()
            .await;
        let (mut driver, tmp) = scripted_write_edit_driver(&provider);
        let (queue, tx, mut rx) = event_harness();

        driver
            .run_user_input(UserSubmission::text("write big.rs"), &queue, &tx)
            .await
            .unwrap();

        let events = drain_events(&mut rx);
        assert_eq!(tool_results(&events).len(), 2);
        assert!(tool_results(&events)[0].2.contains("wrote `"));
        let on_disk = std::fs::read_to_string(tmp.path().join("big.rs")).unwrap();
        assert!(on_disk.contains("REPLACED_NEEDLE"));
        let rows = driver
            .session
            .db
            .list_tool_calls_for_session(driver.session.id)
            .await
            .unwrap();
        assert_eq!(
            rows[0].wire_input_json["content"],
            serde_json::json!(content),
            "durable audit rows keep full write args"
        );

        let posts = provider_posts(&provider);
        assert_eq!(posts.len(), 3);
        let first_messages = chat_messages(&posts[0]);
        let second_messages = chat_messages(&posts[1]);
        let third_messages = chat_messages(&posts[2]);
        let second_write_calls = assistant_tool_call_messages(second_messages);
        assert_eq!(second_write_calls.len(), 1);
        assert_eq!(
            tool_call_arguments(second_write_calls[0])["content"],
            serde_json::json!(content),
            "the latest assistant turn is not rewritten"
        );
        let write_calls = assistant_tool_call_messages(third_messages);
        let write_calls: Vec<_> = write_calls
            .into_iter()
            .filter(|message| message["tool_calls"][0]["function"]["name"] == "write")
            .collect();
        assert_eq!(write_calls.len(), 1);
        let args = tool_call_arguments(write_calls[0]);
        assert_eq!(args["path"], serde_json::json!("big.rs"));
        assert_eq!(
            args["content"],
            serde_json::json!(crate::engine::write_edit_arg_elision::applied_marker(
                content.len()
            ))
        );
        let third_body = serde_json::to_string(&posts[2].body).unwrap();
        assert!(
            !third_body.contains(&content),
            "applied write content must leave requests after the turn settles"
        );

        let prefix_at = third_messages
            .iter()
            .position(|message| {
                message_role(message) == "assistant" && message.get("tool_calls").is_some()
            })
            .expect("second request includes the settled write call");
        assert_eq!(
            serde_json::to_vec(first_messages).unwrap(),
            serde_json::to_vec(&third_messages[..prefix_at]).unwrap(),
            "prefix before the elided call must stay byte-stable"
        );
    });
}

#[test]
fn follow_up_edit_against_an_elided_write_succeeds() {
    crate::test_env::run_async_with_large_stack(|| async {
        let content = long_write_content();
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: "write-large".into(),
                name: "write".into(),
                arguments: serde_json::json!({
                    "path": "big.rs",
                    "content": content
                }),
            })
            .turn(Turn::ToolCall {
                id: "edit-needle".into(),
                name: "edit".into(),
                arguments: serde_json::json!({
                    "path": "big.rs",
                    "old_string": "UNIQUE_NEEDLE_TO_REPLACE",
                    "new_string": "REPLACED_NEEDLE"
                }),
            })
            .turn(Turn::Text("edited the applied file.".into()))
            .start()
            .await;
        let (mut driver, tmp) = scripted_write_edit_driver(&provider);
        let (queue, tx, mut rx) = event_harness();

        driver
            .run_user_input(UserSubmission::text("write then edit big.rs"), &queue, &tx)
            .await
            .unwrap();

        let events = drain_events(&mut rx);
        let results = tool_results(&events);
        assert_eq!(results.len(), 2);
        assert!(results[0].2.contains("wrote `"), "{}", results[0].2);
        assert!(results[1].2.contains("edited `"), "{}", results[1].2);
        let on_disk = std::fs::read_to_string(tmp.path().join("big.rs")).unwrap();
        assert!(on_disk.contains("REPLACED_NEEDLE"));
        assert!(!on_disk.contains("UNIQUE_NEEDLE_TO_REPLACE"));
    });
}

#[test]
fn failed_write_keeps_args_on_the_next_request() {
    crate::test_env::run_async_with_large_stack(|| async {
        let content = long_write_content();
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: "write-fail".into(),
                name: "write".into(),
                arguments: serde_json::json!({
                    "path": "blocked/file.md",
                    "content": content
                }),
            })
            .turn(Turn::Text("handled the failed write.".into()))
            .start()
            .await;
        let (mut driver, tmp) = scripted_write_edit_driver(&provider);
        std::fs::write(tmp.path().join("blocked"), "not a directory").unwrap();
        let (queue, tx, mut rx) = event_harness();

        driver
            .run_user_input(UserSubmission::text("write blocked path"), &queue, &tx)
            .await
            .unwrap();

        let events = drain_events(&mut rx);
        assert_eq!(tool_results(&events).len(), 0);
        assert!(
            events.iter().any(|event| matches!(
                event,
                TurnEvent::ToolError { tool, error, .. }
                    if tool == "write" && error.contains("Error:")
            )),
            "{events:?}"
        );

        let posts = provider_posts(&provider);
        assert_eq!(posts.len(), 2);
        let write_calls = assistant_tool_call_messages(chat_messages(&posts[1]));
        assert_eq!(write_calls.len(), 1);
        let args = tool_call_arguments(write_calls[0]);
        assert_eq!(args["content"], serde_json::json!(content));
        let second_body = serde_json::to_string(&posts[1].body).unwrap();
        assert!(
            second_body.contains(&content),
            "failed write args must stay visible"
        );
    });
}

#[test]
fn parallel_lane_respects_delegation_max_parallel_fifo() {
    crate::test_env::run_async_with_large_stack(|| async {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ParallelToolCalls(vec![
                (
                    "read-alpha".into(),
                    "fifo_lane".into(),
                    serde_json::json!({ "id": "alpha" }),
                ),
                (
                    "read-beta".into(),
                    "fifo_lane".into(),
                    serde_json::json!({ "id": "beta" }),
                ),
                (
                    "read-gamma".into(),
                    "fifo_lane".into(),
                    serde_json::json!({ "id": "gamma" }),
                ),
                (
                    "read-delta".into(),
                    "fifo_lane".into(),
                    serde_json::json!({ "id": "delta" }),
                ),
                // An unknown-effect call is a real serial barrier.  It is
                // intentionally after the over-limit read lane so the parent
                // cannot resume until every queued lane member has settled.
                (
                    "serial-unknown".into(),
                    "not-a-real-tool".into(),
                    serde_json::json!({}),
                ),
            ]))
            .turn(Turn::Text(
                "All lane members drained before the barrier.".into(),
            ))
            .start()
            .await;
        let (mut driver, tmp) = scripted_driver(&provider);
        let state = FifoLaneState::new();
        let old = driver.stack[0].agent.clone();
        driver.stack[0].agent = Arc::new(Agent {
            name: old.name.clone(),
            system: old.system.clone(),
            role_prompt: old.role_prompt.clone(),
            tools: crate::engine::tool::ToolBox::new().with(Arc::new(FifoLaneTool {
                state: state.clone(),
            })),
            model: old.model.clone(),
            params: old.params.clone(),
            scan_tool_results: old.scan_tool_results,
            tool_steering: old.tool_steering,
            posture: old.posture.clone(),
            context_policy: old.context_policy.clone(),
            lock_identity: "Build".to_string(),
            write_scope: None,
            workspace_lease: old.workspace_lease.clone(),
            delegated: old.delegated,
            delegation_recursion: old.delegation_recursion.clone(),
            vnext_grant: old.vnext_grant.clone(),
            env_overlay: old.env_overlay.clone(),
            definition: old.definition.clone(),
            assistant_identity_prefix: None,
            mcp_resolver: old.mcp_resolver.clone(),
        });
        std::fs::create_dir_all(tmp.path().join(".cockpit/providers")).unwrap();
        std::fs::write(
            tmp.path().join(".cockpit/config.json"),
            serde_json::json!({
                "active_model": { "provider": "lmstudio", "model": "local" },
                "delegation": { "maxParallel": 2 }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            tmp.path().join(".cockpit/providers/lmstudio.json"),
            serde_json::json!({
                "url": provider.base_url(),
                "wireApi": "completions",
                "models": [{ "id": "local" }]
            })
            .to_string(),
        )
        .unwrap();
        driver.refresh_config_from_disk_for_tests();
        let (queue, tx, mut rx) = event_harness();

        {
            let run = driver.run_user_input(UserSubmission::text("read both"), &queue, &tx);
            tokio::pin!(run);

            tokio::select! {
                result = &mut run => panic!("driver completed before the over-limit lane blocked: {result:?}"),
                () = wait_until_started(&state, 2) => {}
            }
            // Removing `ordinary_active + delegates.len() >= max_parallel` would
            // admit gamma/delta while alpha/beta are still held. Source-order
            // folding would still be green; in-flight count is the bound.
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            assert_eq!(state.started(), vec!["alpha", "beta"]);
            assert_eq!(state.in_flight(), 2);
            assert_eq!(state.max_in_flight(), 2);

            state.release("alpha");
            tokio::select! {
                result = &mut run => panic!("driver completed before the FIFO successor started: {result:?}"),
                () = wait_until_started(&state, 3) => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            assert_eq!(state.started(), vec!["alpha", "beta", "gamma"]);
            assert!(
                state.in_flight() <= 2,
                "FIFO successor must reuse the freed slot, not grow past max_parallel"
            );
            assert_eq!(state.max_in_flight(), 2);

            state.release("beta");
            state.release("gamma");
            tokio::select! {
                result = &mut run => panic!("driver completed before the last queued member started: {result:?}"),
                () = wait_until_started(&state, 4) => {}
            }
            assert_eq!(
                state.started(),
                vec!["alpha", "beta", "gamma", "delta"],
                "queued members start FIFO as capacity frees"
            );
            state.release("delta");
            run.await.unwrap();
        }
        assert_eq!(state.max_in_flight(), 2);

        let events = drain_events(&mut rx);
        let results = tool_results(&events);
        assert_eq!(
            results.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(),
            vec![
                "read-alpha",
                "read-beta",
                "read-gamma",
                "read-delta",
                "serial-unknown",
            ]
        );
        assert!(results[0].2.contains("alpha body"));
        assert!(results[1].2.contains("beta body"));
        assert!(results[2].2.contains("gamma body"));
        assert!(results[3].2.contains("delta body"));
        assert!(results[4].2.starts_with("Error:"));

        let captured = provider.captured();
        let second_messages = chat_messages(&captured[1]);
        let result_ids = second_messages
            .iter()
            .filter(|message| message_role(message) == "tool")
            .map(|message| message["tool_call_id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            result_ids,
            vec![
                "read-alpha",
                "read-beta",
                "read-gamma",
                "read-delta",
                "serial-unknown",
            ],
            "the four read-only calls (over maxParallel=2) drain FIFO before the serial barrier is folded into the next real provider request"
        );

        // Production Driver durability follows source order too, even if the
        // read futures complete in the opposite order. Check each durable
        // lifecycle phase independently; message folding alone would not catch
        // completion-ordered audit commits.
        let durable = session_events(&driver).await;
        for kind in ["tool_call_started", "tool_call", "tool_call_completed"] {
            assert_eq!(
                durable
                    .iter()
                    .filter(|event| event.kind == kind)
                    .filter_map(|event| event.call_id.as_deref())
                    .collect::<Vec<_>>(),
                vec![
                    "read-alpha",
                    "read-beta",
                    "read-gamma",
                    "read-delta",
                    "serial-unknown",
                ],
                "{kind} durability must remain in provider source order"
            );
        }
        let continuations = driver
            .session
            .db
            .read({
                let session_id = driver.session.id;
                move |conn| crate::db::Db::list_turn_scheduler_continuations_conn(conn, session_id)
            })
            .await
            .unwrap();
        assert_eq!(
            continuations
                .iter()
                .map(|row| row.call_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "read-alpha",
                "read-beta",
                "read-gamma",
                "read-delta",
                "serial-unknown",
            ]
        );
        assert!(
            continuations
                .iter()
                .all(|row| row.terminal_outcome.as_deref() == Some("completed"))
        );
        assert!(
            continuations.iter().all(|row| {
                row.terminal_result_body.as_deref().is_some_and(|body| {
                    body != crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY
                })
            }),
            "every settled production-lane call persists a non-interruption paired body"
        );
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

// ---------------------------------------------------------------------------
// Leak-report buffered delivery + barrier, end-to-end through `run_turn` on the
// real ScriptedProvider (increment 2, AC1/AC3). `scripted_read_driver` builds an
// UNTRUSTED, tool-capable route, so `report_leak` is advertised and the buffered
// delivery sink engages. These are the real security-boundary integration tests
// the sink unit tests cannot cover: that `run_turn` wires the eligible route to
// the WRAPPED sender, withholds a streamed token on a contained turn (persisting
// nothing), and flushes it on a released turn.
// ---------------------------------------------------------------------------

/// A single SSE completion stream that emits a prose text delta (carrying
/// `prose`) and THEN a `report_leak` tool call (carrying `secret`) — mirroring
/// the harness's own chat-completions chunk shapes (`emit_chat_turn` +
/// `emit_chat_tool_calls`), concatenated into one stream. `Turn::Text` /
/// `Turn::ToolCall` cannot express a single stream carrying both, so this uses
/// `Turn::RawSse`.
fn text_then_report_leak_sse(prose: &str, secret: &str) -> String {
    let content = serde_json::json!({
        "id": "c", "model": "local",
        "choices": [{ "delta": { "content": prose }, "finish_reason": null }],
        "usage": null
    });
    let args = serde_json::json!({ "secret": secret, "source": "model_output" }).to_string();
    let tool = serde_json::json!({
        "id": "c", "model": "local",
        "choices": [{ "delta": { "tool_calls": [{
            "index": 0, "id": "leak-1", "type": "function",
            "function": { "name": "report_leak", "arguments": args }
        }] }, "finish_reason": null }],
        "usage": null
    });
    let finish = serde_json::json!({
        "id": "c", "model": "local",
        "choices": [{ "delta": {}, "finish_reason": "tool_calls" }],
        "usage": null
    });
    format!("data: {content}\n\ndata: {tool}\n\ndata: {finish}\n\ndata: [DONE]\n\n")
}

#[tokio::test(start_paused = true)]
async fn report_leak_turn_withholds_stream_and_persists_no_plaintext() {
    tokio::time::resume();
    const PROSE_TOKEN: &str = "PLANTED-STREAM-TOKEN-a1b2c3";
    const SECRET: &str = "PLANTED-SECRET-VALUE-d4e5f6";

    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::RawSse(text_then_report_leak_sse(
            &format!("here is prose {PROSE_TOKEN} and more"),
            SECRET,
        )))
        // Fallback in case the driver continues after the contained turn; carries
        // NEITHER the streamed token NOR the secret, so assertions hold either way.
        .turn(Turn::Text("done".into()))
        .start()
        .await;

    // Untrusted + tool-capable => report_leak advertised + buffered sink engaged.
    let (mut driver, _tmp) = scripted_read_driver(&provider);
    assert!(
        !driver.stack[0].agent.model.is_trusted(),
        "this route must be untrusted for the sink to engage"
    );
    let (queue, tx, mut rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("please process this"), &queue, &tx)
        .await
        .unwrap();

    let events = drain_events(&mut rx);
    let events_blob = format!("{events:?}");
    // The streamed prose token was WITHHELD on this contained turn — it never
    // reached the live client event stream. A regression passing `tx` directly to
    // the completion (turn_phases.rs), or dropping the eligibility gate, would
    // have streamed it live here and failed this assertion.
    assert!(
        !events_blob.contains(PROSE_TOKEN),
        "the withheld streamed token must not reach the live event stream: {events_blob}"
    );
    // The reported secret never crosses to the client stream either.
    assert!(
        !events_blob.contains(SECRET),
        "the reported secret must not reach the live event stream"
    );
    // report_leak was NOT dispatched as a generic tool (barrier partitioned it).
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, TurnEvent::ToolStart { tool, .. } if tool == "report_leak")),
        "report_leak must never dispatch as a generic tool"
    );

    // Durable state carries NEITHER the streamed token NOR the secret: the
    // sensitive turn cleared its assistant text and did not persist its choice.
    let history = history_text(&driver.stack[0].history);
    assert!(
        !history.contains(PROSE_TOKEN) && !history.contains(SECRET),
        "durable frame history must not contain withheld plaintext: {history}"
    );
    let rows = session_events(&driver).await;
    let durable: String = rows
        .iter()
        .map(|row| serde_json::to_string(&row.data).unwrap())
        .collect();
    assert!(
        !durable.contains(PROSE_TOKEN) && !durable.contains(SECRET),
        "durable session log must not contain withheld plaintext"
    );
    assert!(
        !rows.iter().any(|row| row.kind == "assistant_message"
            && serde_json::to_string(&row.data)
                .unwrap()
                .contains(PROSE_TOKEN)),
        "no assistant_message may persist the withheld token"
    );

    // Defense in depth: the secret never left on any outbound provider request.
    let wire: String = provider_posts(&provider)
        .iter()
        .map(|request| request.body.to_string())
        .collect();
    assert!(
        !wire.contains(SECRET),
        "the reported secret must not appear on any outbound request"
    );
}

#[tokio::test(start_paused = true)]
async fn eligible_route_non_sensitive_turn_flushes_stream() {
    tokio::time::resume();
    const FLUSH_TOKEN: &str = "FLUSHED-STREAM-TOKEN-e5f6a7";

    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text(format!("assistant prose {FLUSH_TOKEN} end")))
        .start()
        .await;

    // Same untrusted, tool-capable (sink-engaged) route as the contained test.
    let (mut driver, _tmp) = scripted_read_driver(&provider);
    assert!(!driver.stack[0].agent.model.is_trusted());
    let (queue, tx, mut rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("hi"), &queue, &tx)
        .await
        .unwrap();

    let events = drain_events(&mut rx);
    // Positive control: on a non-sensitive (Released) turn the withheld deltas ARE
    // flushed, so the streamed token DOES surface on the client stream — proving
    // the withholding above is real containment, not a dead path.
    let delta_blob: String = events
        .iter()
        .filter_map(|event| match event {
            // The released deltas now surface on the typed display stream
            // (AssistantDisplayTextDelta), the client-facing streaming event.
            TurnEvent::AssistantDisplayTextDelta { delta, .. } => Some(delta.clone()),
            _ => None,
        })
        .collect();
    assert!(
        delta_blob.contains(FLUSH_TOKEN),
        "a Released turn must flush the withheld delta to the client stream: {events:?}"
    );
    // ...and the assistant message is persisted with it.
    assert!(history_text(&driver.stack[0].history).contains(FLUSH_TOKEN));
    let rows = session_events(&driver).await;
    assert!(
        rows.iter().any(|row| row.kind == "assistant_message"
            && serde_json::to_string(&row.data)
                .unwrap()
                .contains(FLUSH_TOKEN)),
        "the released turn's assistant_message must persist the flushed text"
    );
}

// ---------------------------------------------------------------------------
// Root stop-gate boundary wiring (increment 2B-ii-a). These drive the REAL
// main-loop `TurnOutcome::Done` boundary through `run_user_input`. The stop
// hook command is unresolvable, so it fails open (executable-not-found) WITHOUT
// spawning a process; a `hook_run` row is still recorded whenever the gate is
// ENTERED — the wiring signal. Absence of the row proves the gate was NOT
// entered. On dead-code HEAD (no wiring) the genuine-Done row is missing, so
// that test fails there.
// ---------------------------------------------------------------------------

/// A registry carrying one `stop`/`end_turn` hook and one `stopFailure`/`network`
/// hook, both unresolvable (fail-open), so a test can assert which gate fired.
fn stop_and_stop_failure_registry() -> crate::config::extended::hooks::HookRegistry {
    use crate::config::extended::hooks::{HookEvent, HookOrigin, HookRegistry, ResolvedHook};
    let mk = |event: HookEvent, matcher: &str| ResolvedHook {
        event,
        matcher: Some([matcher.to_string()].into_iter().collect()),
        command: vec!["cockpit-stop-hook-does-not-exist".to_string()],
        timeout_secs: 5,
        env: std::collections::BTreeMap::new(),
        origin: HookOrigin::for_test("project:abcdef0123456789:0"),
        source_config_path: std::path::PathBuf::from("/tmp/test/config.json"),
        source_directory: std::path::PathBuf::from("/tmp/test"),
        execution: crate::config::extended::hooks::HookExecutionProvenance::Ambient,
    };
    HookRegistry {
        hooks: vec![
            mk(HookEvent::Stop, "end_turn"),
            mk(HookEvent::StopFailure, "network"),
        ],
        warnings: Vec::new(),
    }
}

#[tokio::test(start_paused = true)]
async fn root_stop_gate_fires_on_genuine_done() {
    tokio::time::resume();
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("all finished".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(crate::config::extended::hooks::HookEvent::Stop, "end_turn"),
    );
    let (queue, tx, _rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("do the thing"), &queue, &tx)
        .await
        .unwrap();

    assert_eq!(
        observe_hook_events(&driver, "stop").await,
        vec!["failed".to_string()],
        "a genuine root Done must consult the stop gate exactly once"
    );
}

#[tokio::test(start_paused = true)]
async fn root_stop_gate_not_fired_for_lookalike_matcher() {
    tokio::time::resume();
    let provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Text("all finished".into()))
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    // The `stop` matcher is closed to `end_turn`; a hook matched only on a
    // sibling value must NOT fire at the root Done boundary.
    inject_hooks(
        &mut driver,
        observe_boundary_registry(crate::config::extended::hooks::HookEvent::Stop, "cancelled"),
    );
    let (queue, tx, _rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("do the thing"), &queue, &tx)
        .await
        .unwrap();

    assert!(
        observe_hook_events(&driver, "stop").await.is_empty(),
        "a lookalike-matcher stop hook must not fire on end_turn"
    );
}

#[tokio::test]
async fn root_stop_gate_not_entered_on_inference_error() {
    // A terminal inference failure ends the attempt from the `Err(..)` arm
    // BEFORE the `Done` match — so the stop gate is never entered. The
    // `stopFailure` hook DOES fire on the same run, proving the turn genuinely
    // reached the error path (non-vacuous contrast), while `stop` records
    // nothing.
    let (mut driver, _tmp) = test_driver_without_network(1);
    driver
        .session
        .set_active_model("lmstudio", "local")
        .unwrap();
    inject_hooks(&mut driver, stop_and_stop_failure_registry());
    let (queue, tx, _rx) = event_harness();

    driver
        .run_user_input(UserSubmission::text("will fail to connect"), &queue, &tx)
        .await
        .unwrap();

    assert_eq!(
        observe_hook_events(&driver, "stopFailure").await,
        vec!["failed".to_string()],
        "an inference failure must fire stopFailure (proves the error path ran)"
    );
    assert!(
        observe_hook_events(&driver, "stop").await.is_empty(),
        "an inference error must never enter or reopen the root stop gate"
    );
}

#[tokio::test(start_paused = true)]
async fn root_stop_gate_not_entered_on_cancellation() {
    let mut provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::Hang)
        .start()
        .await;
    let (mut driver, _tmp) = scripted_driver(&provider);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(crate::config::extended::hooks::HookEvent::Stop, "end_turn"),
    );
    let cancel = driver.cancel_handle();
    let (queue, tx, _rx) = event_harness();

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

    assert!(
        observe_hook_events(&driver, "stop").await.is_empty(),
        "a cancelled turn must never enter or reopen the root stop gate"
    );
}
