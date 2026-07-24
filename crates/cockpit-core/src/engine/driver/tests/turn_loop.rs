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
        delegated: old.delegated,
        delegation_recursion: old.delegation_recursion.clone(),
        env_overlay: old.env_overlay.clone(),
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

fn write_max_primary_rounds_config(root: &std::path::Path, max_rounds: u32) {
    let cockpit = root.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "maxPrimaryRounds": max_rounds
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
async fn turn_loop_tool_call_result_feeds_second_inference() {
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
}

#[tokio::test]
async fn turn_loop_parallel_tool_calls_preserve_order_and_call_id_pairing() {
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
}

#[tokio::test]
async fn turn_loop_tool_error_becomes_tool_result_not_turn_abort() {
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
}

#[tokio::test]
async fn turn_loop_max_rounds_guard_terminates_turn() {
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
