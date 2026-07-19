use super::*;

fn exact_model_selector(model: &str) -> crate::engine::model_roles::DelegationModelSelector {
    crate::engine::model_roles::DelegationModelSelector::Exact {
        selector: format!("lmstudio:{model}"),
        required_capabilities: Vec::new(),
        min_context_tokens: None,
    }
}

fn root_child_cwd(driver: &Driver) -> ChildCwd {
    ChildCwd {
        requested: None,
        resolved: driver.cwd.clone(),
    }
}

fn write_delegated_model_config(driver: &Driver, models: &[&str]) {
    let config_dir = driver.cwd.join(".cockpit");
    let providers_dir = config_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        r#"{
          "agent_chooses_subagent_model": true,
          "active_model": { "provider": "lmstudio", "model": "local" }
        }"#,
    )
    .unwrap();
    let models_json = models
        .iter()
        .map(|model| {
            serde_json::json!({
                "id": model,
                "subagent_invokable": true,
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        providers_dir.join("lmstudio.json"),
        serde_json::json!({
            "url": test_provider_base_url(),
            "models": models_json,
        })
        .to_string(),
    )
    .unwrap();
}

fn failing_provider_base_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            let body = r#"{"error":{"message":"server failed"}}"#;
            let resp = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = std::io::Write::write_all(&mut stream, resp.as_bytes());
            let _ = std::io::Write::flush(&mut stream);
        }
    });
    format!("http://{addr}/v1")
}

fn write_delegated_model_config_with_backup(driver: &Driver, primary_url: &str, backup_url: &str) {
    let config_dir = driver.cwd.join(".cockpit");
    let providers_dir = config_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        r#"{
          "agent_chooses_subagent_model": true,
          "active_model": { "provider": "lmstudio", "model": "local" }
        }"#,
    )
    .unwrap();
    std::fs::write(
        providers_dir.join("lmstudio.json"),
        serde_json::json!({
            "url": test_provider_base_url(),
            "models": [{ "id": "local" }],
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        providers_dir.join("flaky.json"),
        serde_json::json!({
            "url": primary_url,
            "backup": { "provider": "reliable", "model": "backup-model" },
            "models": [{ "id": "child-flaky", "subagent_invokable": true }],
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        providers_dir.join("reliable.json"),
        serde_json::json!({
            "url": backup_url,
            "models": [{ "id": "backup-model", "subagent_invokable": true }],
        })
        .to_string(),
    )
    .unwrap();
}

fn seed_task_payload(driver: &Driver, task_call_id: &str, label: &str, child_agent: &str) {
    driver
        .persist_delegation_payload(
            task_call_id,
            Some(&format!("fn-{task_call_id}")),
            "Build",
            label,
            child_agent,
            &format!("{label} prompt"),
        )
        .unwrap();
}

fn single_task(
    driver: &Driver,
    child_agent: &str,
    task_call_id: &str,
    model: Option<crate::engine::model_roles::DelegationModelSelector>,
    resume_handle: Option<&str>,
) -> SingleNoninteractiveTask {
    SingleNoninteractiveTask {
        child_agent: child_agent.to_string(),
        brief: "look around".to_string(),
        model,
        remaining_depth: Some(0),
        why: "test".to_string(),
        resume_handle: resume_handle.map(str::to_string),
        child_cwd: root_child_cwd(driver),
        granted_tools: Vec::new(),
        prefill_seeds: Vec::new(),
        todo_ids: Vec::new(),
        skill_seed: Vec::new(),
        child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        repair_notes: Vec::new(),
        task_call_id: task_call_id.to_string(),
        task_function_call_id: Some(format!("fn-{task_call_id}")),
    }
}

fn batch_entry(
    label: &str,
    child_agent: &str,
    model: Option<crate::engine::model_roles::DelegationModelSelector>,
) -> crate::engine::agent::BatchTaskEntry {
    crate::engine::agent::BatchTaskEntry {
        label: label.to_string(),
        child_agent: child_agent.to_string(),
        prompt: format!("{label} prompt"),
        model,
        remaining_depth: Some(0),
        resume_handle: None,
        cwd: None,
        granted_tools: Vec::new(),
        seeds: Vec::new(),
        todo_ids: Vec::new(),
        skill_seed: Vec::new(),
        output_dir: None,
    }
}

fn drain_turn_events(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

fn child_routing_for(model: &str) -> ChildRoutingMetadata {
    ChildRoutingMetadata {
        provider: "lmstudio".to_string(),
        model: model.to_string(),
        trusted_only: false,
        model_trusted: true,
        routing: serde_json::json!({
            "provider": "lmstudio",
            "resolved_model": model,
            "fallback_decision": "none",
        }),
    }
}

#[tokio::test]
async fn noninteractive_event_forwarder_wraps_child_events() {
    let (child_tx, child_rx) = mpsc::channel(8);
    let (parent_tx, mut parent_rx) = mpsc::channel(8);
    let target = NoninteractiveSteerTarget::new("task-1", "default");
    let forwarder = spawn_noninteractive_event_forwarder(child_rx, Some(parent_tx), Some(target));

    child_tx
        .send(TurnEvent::AssistantTextDelta {
            agent: "Explore".into(),
            delta: "hel".into(),
        })
        .await
        .unwrap();
    child_tx
        .send(TurnEvent::AssistantTextDelta {
            agent: "Explore".into(),
            delta: "lo".into(),
        })
        .await
        .unwrap();
    child_tx
        .send(TurnEvent::ToolStart {
            agent: "Explore".into(),
            call_id: "call-1".into(),
            tool: "read".into(),
            args: serde_json::json!({"path":"README.md"}),
        })
        .await
        .unwrap();
    drop(child_tx);
    forwarder.await.unwrap();

    match parent_rx.recv().await.unwrap() {
        TurnEvent::NestedTurn {
            task_call_id,
            label,
            parent_task_call_id,
            inner,
        } => {
            assert_eq!(task_call_id, "task-1");
            assert_eq!(label, "default");
            assert_eq!(parent_task_call_id, None);
            assert!(matches!(
                inner.as_ref(),
                TurnEvent::AssistantTextDelta { agent, delta }
                    if agent == "Explore" && delta == "hello"
            ));
        }
        other => panic!("expected nested assistant delta, got {other:?}"),
    }
    match parent_rx.recv().await.unwrap() {
        TurnEvent::NestedTurn { inner, .. } => assert!(matches!(
            inner.as_ref(),
            TurnEvent::ToolStart { agent, call_id, tool, .. }
                if agent == "Explore" && call_id == "call-1" && tool == "read"
        )),
        other => panic!("expected nested tool start, got {other:?}"),
    }
    assert!(parent_rx.recv().await.is_none());
}

#[tokio::test]
async fn noninteractive_single_spawn_amends_with_child_routing() {
    let (mut driver, _tmp) = test_driver(8);
    write_delegated_model_config(&driver, &["local", "child-single"]);
    seed_task_delegation(&driver, "task-single-routing", "default");
    seed_task_payload(&driver, "task-single-routing", "default", "explore");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(128);
    let completion = driver
        .execute_single_noninteractive_task(
            single_task(
                &driver,
                "explore",
                "task-single-routing",
                Some(exact_model_selector("child-single")),
                None,
            ),
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(
        completion.child_routing.as_ref().unwrap().model,
        "child-single"
    );
    let events = drain_turn_events(&mut rx);
    let spawn_idx = events
        .iter()
        .position(|event| matches!(event, TurnEvent::SubagentSpawned { task_call_id, .. } if task_call_id == "task-single-routing"))
        .expect("spawn event");
    let routing_idx = events
        .iter()
        .position(|event| matches!(event, TurnEvent::SubagentRouting { task_call_id, .. } if task_call_id == "task-single-routing"))
        .expect("routing amend event");
    assert!(spawn_idx < routing_idx);
    match &events[routing_idx] {
        TurnEvent::SubagentRouting {
            child,
            task_call_id,
            label,
            model,
            routing,
            ..
        } => {
            assert_eq!(child, "explore");
            assert_eq!(task_call_id, "task-single-routing");
            assert_eq!(label, "default");
            assert_eq!(model, "child-single");
            assert_eq!(routing["resolved_model"], "child-single");
            assert_ne!(routing["resolved_model"], "local");
        }
        other => panic!("expected SubagentRouting, got {other:?}"),
    }
}

#[test]
fn noninteractive_single_fallback_amends_and_reports_backup_decision() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (mut driver, _tmp) = test_driver(8);
                    let primary_url = failing_provider_base_url();
                    let backup_url = test_provider_base_url();
                    write_delegated_model_config_with_backup(&driver, &primary_url, &backup_url);
                    seed_task_delegation(&driver, "task-single-fallback", "default");
                    seed_task_payload(&driver, "task-single-fallback", "default", "explore");
                    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);

                    let completion = driver
                        .execute_single_noninteractive_task(
                            single_task(
                                &driver,
                                "explore",
                                "task-single-fallback",
                                Some(crate::engine::model_roles::DelegationModelSelector::Exact {
                                    selector: "flaky:child-flaky".to_string(),
                                    required_capabilities: Vec::new(),
                                    min_context_tokens: None,
                                }),
                                None,
                            ),
                            &tx,
                            tokio_util::sync::CancellationToken::new(),
                        )
                        .await
                        .unwrap();

                    let routing = completion.child_routing.as_ref().unwrap();
                    assert_eq!(routing.model, "child-flaky");
                    assert_eq!(routing.routing["fallback_decision"], "backup");

                    let events = drain_turn_events(&mut rx);
                    let routing_events = events
                        .iter()
                        .filter_map(|event| match event {
                            TurnEvent::SubagentRouting {
                                task_call_id,
                                routing,
                                ..
                            } if task_call_id == "task-single-fallback" => Some(routing),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(routing_events.len(), 2);
                    assert_eq!(routing_events[0]["fallback_decision"], "none");
                    assert_eq!(routing_events[1]["fallback_decision"], "backup");

                    let _ = driver
                        .finalize_single_noninteractive_task(completion, &tx, true)
                        .await
                        .unwrap();
                    let report_event = driver
                        .session
                        .db
                        .list_session_events(driver.session.id)
                        .unwrap()
                        .into_iter()
                        .find(|event| {
                            event.kind == "subagent_report"
                                && event.call_id.as_deref() == Some("task-single-fallback")
                        })
                        .expect("durable subagent_report event");
                    assert_eq!(report_event.data["routing"]["fallback_decision"], "backup");
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[tokio::test]
async fn noninteractive_batch_spawn_amends_each_child_routing() {
    let (mut driver, _tmp) = test_driver(8);
    write_delegated_model_config(&driver, &["local", "child-first", "child-second"]);
    seed_batch_task_delegation(&driver, "task-batch-routing", &["first", "second"]);
    seed_task_payload(&driver, "task-batch-routing", "first", "explore");
    seed_task_payload(&driver, "task-batch-routing", "second", "scout");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    let task = BatchNoninteractiveTask {
        entries: vec![
            batch_entry(
                "first",
                "explore",
                Some(exact_model_selector("child-first")),
            ),
            batch_entry(
                "second",
                "scout",
                Some(exact_model_selector("child-second")),
            ),
        ],
        child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-batch-routing".to_string(),
        task_function_call_id: Some("fn-task-batch-routing".to_string()),
    };

    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(completion.children.len(), 2);

    let events = drain_turn_events(&mut rx);
    let mut amends: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            TurnEvent::SubagentRouting {
                task_call_id,
                label,
                child,
                model,
                routing,
                ..
            } if task_call_id == "task-batch-routing" => Some((
                label.as_str(),
                child.as_str(),
                model.as_str(),
                routing.clone(),
            )),
            _ => None,
        })
        .collect();
    amends.sort_by_key(|(label, _, _, _)| *label);

    assert_eq!(amends.len(), 2);
    assert_eq!(amends[0].0, "first");
    assert_eq!(amends[0].1, "explore");
    assert_eq!(amends[0].2, "child-first");
    assert_eq!(amends[0].3["resolved_model"], "child-first");
    assert_eq!(amends[1].0, "second");
    assert_eq!(amends[1].1, "scout");
    assert_eq!(amends[1].2, "child-second");
    assert_eq!(amends[1].3["resolved_model"], "child-second");
}

#[tokio::test]
async fn interactive_spawn_amends_with_child_routing() {
    let (driver, _tmp) = test_driver(8);
    write_delegated_model_config(&driver, &["local", "interactive-child"]);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let child = driver
        .load_interactive_child_or_tool_error(InteractiveChildLoadRequest {
            child_agent: "explore",
            granted_tools: Vec::new(),
            model: Some(exact_model_selector("interactive-child")),
            child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            task_call_id: "task-interactive-routing",
            task_function_call_id: Some("fn-task-interactive-routing".to_string()),
            repair_notes: &[],
        })
        .unwrap();
    let child_routing = ChildRoutingMetadata::from_model(&child.model);

    driver
        .emit_subagent_routing_amend(
            &tx,
            "explore",
            "task-interactive-routing",
            "default",
            &child_routing,
        )
        .await;

    let events = drain_turn_events(&mut rx);
    match events.as_slice() {
        [
            TurnEvent::SubagentRouting {
                child,
                task_call_id,
                label,
                model,
                routing,
                ..
            },
        ] => {
            assert_eq!(child, "explore");
            assert_eq!(task_call_id, "task-interactive-routing");
            assert_eq!(label, "default");
            assert_eq!(model, "interactive-child");
            assert_eq!(routing["resolved_model"], "interactive-child");
        }
        other => panic!("expected one interactive routing amend, got {other:?}"),
    }
}

#[tokio::test]
async fn pending_noninteractive_completion_routes_by_task_call_id() {
    let (mut driver, _tmp) = test_driver(8);
    let tx = driver.noninteractive_complete_tx.clone();
    tx.send(BackgroundNoninteractiveCompletion::Single {
        task_call_id: "task-a".to_string(),
        task_function_call_id: Some("fn-task-a".to_string()),
        result: Box::new(Ok(single_noninteractive_completion("task-a", "a done"))),
    })
    .await
    .unwrap();
    tx.send(BackgroundNoninteractiveCompletion::Single {
        task_call_id: "task-b".to_string(),
        task_function_call_id: Some("fn-task-b".to_string()),
        result: Box::new(Ok(single_noninteractive_completion("task-b", "b done"))),
    })
    .await
    .unwrap();

    let completion = driver
        .recv_noninteractive_completion_for("task-b")
        .await
        .expect("task-b completion");
    assert_eq!(completion.task_call_id(), "task-b");
    assert_eq!(driver.pending_noninteractive_completions.len(), 1);
    assert_eq!(
        driver.pending_noninteractive_completions[0].task_call_id(),
        "task-a"
    );

    let completion = driver
        .recv_noninteractive_completion_for("task-a")
        .await
        .expect("task-a completion");
    assert_eq!(completion.task_call_id(), "task-a");
    assert!(driver.pending_noninteractive_completions.is_empty());
}

#[tokio::test]
async fn delivered_finished_noninteractive_job_is_reaped() {
    let (mut driver, _tmp) = test_driver(8);
    driver.noninteractive_jobs.insert(
        "task-reap".to_string(),
        BackgroundNoninteractiveJob {
            delivered: true,
            handle: tokio::spawn(async {}),
        },
    );
    tokio::task::yield_now().await;

    driver.reap_finished_noninteractive_jobs();

    assert!(!driver.noninteractive_jobs.contains_key("task-reap"));
}

#[tokio::test]
async fn whole_job_cancel_releases_aborted_child_locks() {
    let (mut driver, tmp) = test_driver(8);
    let path = tmp.path().join("held.rs");
    std::fs::write(&path, "fn main() {}\n").unwrap();
    seed_task_delegation(&driver, "task-lock", "default");
    driver.noninteractive_delegations.register_running(
        "task-lock",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver
        .locks
        .acquire(&path, "explore", driver.session.id)
        .unwrap();
    driver.noninteractive_jobs.insert(
        "task-lock".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {
                std::future::pending::<()>().await;
            }),
        },
    );

    let body = driver.dispatch_task_control(
        TaskControlAction::Cancel,
        Some("task-lock".to_string()),
        None,
        None,
    );

    assert!(body.contains("cancelled"), "{body}");
    assert!(driver.locks.holder(&path).is_none());
    assert!(!driver.noninteractive_jobs.contains_key("task-lock"));
}

#[tokio::test]
async fn inline_background_completion_error_keeps_original_task_pairing() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-inline".to_string(),
                task_function_call_id: Some("fn-inline".to_string()),
                result: Box::new(Err(anyhow::anyhow!("child crashed"))),
            }),
            &tx,
        )
        .await
        .unwrap();

    let NoninteractiveCompletionDelivery::Inline(message) = delivery else {
        panic!("inline error should satisfy the open task tool call");
    };
    assert_eq!(tool_result_id(&message), "task-inline");
    assert_eq!(
        tool_result_provider_call_id(&message).as_deref(),
        Some("fn-inline")
    );
    assert!(tool_result_text(&message).contains("child crashed"));
}

#[tokio::test]
async fn backgrounded_completion_error_becomes_async_failed_result_once() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-bg-error", "default");
    driver
        .session
        .db
        .background_task_delegation_child("task-bg-error", "default")
        .unwrap();
    driver.noninteractive_delegations.register_running(
        "task-bg-error",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver
        .noninteractive_delegations
        .background_on_user_input("task-bg-error", "default");
    driver.noninteractive_jobs.insert(
        "task-bg-error".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {}),
        },
    );
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-bg-error".to_string(),
                task_function_call_id: Some("fn-bg-error".to_string()),
                result: Box::new(Err(anyhow::anyhow!("late child crashed"))),
            }),
            &tx,
        )
        .await
        .unwrap();

    let NoninteractiveCompletionDelivery::AsyncUser(text) = delivery else {
        panic!("backgrounded error should be delivered as async user input");
    };
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "failed");
    assert_eq!(json["task_call_id"], "task-bg-error");
    assert_eq!(json["children"][0]["label"], "default");
    assert_eq!(json["children"][0]["status"], "failed");
    assert_eq!(json["children"][0]["error"], "Error: late child crashed");

    let duplicate = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-bg-error".to_string(),
                task_function_call_id: Some("fn-bg-error".to_string()),
                result: Box::new(Err(anyhow::anyhow!("late child crashed again"))),
            }),
            &tx,
        )
        .await
        .unwrap();
    assert!(matches!(duplicate, NoninteractiveCompletionDelivery::None));
}

#[tokio::test]
async fn backgrounded_batch_completion_delivers_one_mixed_status_payload() {
    let (mut driver, _tmp) = test_driver(8);
    seed_batch_task_delegation(&driver, "task-mixed", &["first", "second", "third"]);
    for label in ["first", "second", "third"] {
        driver
            .session
            .db
            .background_task_delegation_child("task-mixed", label)
            .unwrap();
        driver.noninteractive_delegations.register_running(
            "task-mixed",
            label,
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        driver
            .noninteractive_delegations
            .background_on_user_input("task-mixed", label);
    }
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Batch {
                task_call_id: "task-mixed".to_string(),
                task_function_call_id: Some("fn-mixed".to_string()),
                result: Box::new(Ok(BatchNoninteractiveCompletion {
                    task_call_id: "task-mixed".to_string(),
                    task_function_call_id: Some("fn-mixed".to_string()),
                    children: vec![
                        BatchChildCompletion {
                            idx: 0,
                            label: "first".to_string(),
                            child_agent: "explore".to_string(),
                            report: "first report".to_string(),
                            failed: false,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                        BatchChildCompletion {
                            idx: 1,
                            label: "second".to_string(),
                            child_agent: "explore".to_string(),
                            report: "second failed".to_string(),
                            failed: true,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                        BatchChildCompletion {
                            idx: 2,
                            label: "third".to_string(),
                            child_agent: "explore".to_string(),
                            report: "third report".to_string(),
                            failed: false,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                    ],
                    repair_notes: Vec::new(),
                })),
            }),
            &tx,
        )
        .await
        .unwrap();

    let NoninteractiveCompletionDelivery::AsyncUser(text) = delivery else {
        panic!("backgrounded batch should be delivered as one async user input");
    };
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "failed");
    assert_eq!(json["task_call_id"], "task-mixed");
    let children = json["children"].as_array().unwrap();
    assert_eq!(children.len(), 3);
    assert_eq!(children[0]["label"], "first");
    assert_eq!(children[0]["status"], "completed");
    assert_eq!(children[0]["report"], "first report");
    assert_eq!(children[1]["label"], "second");
    assert_eq!(children[1]["status"], "failed");
    assert_eq!(children[1]["error"], "second failed");
    assert_eq!(children[2]["label"], "third");
    assert_eq!(children[2]["status"], "completed");
    assert_eq!(children[2]["report"], "third report");
}

#[tokio::test]
async fn background_single_completion_does_not_apply_stale_shrink() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-single", "default");
    driver
        .noninteractive_delegations
        .background_on_user_input("task-single", "default");
    let foreground_history = vec![
        Message::user("start delegated task"),
        assistant_with_task_call("task-single"),
        Message::user("foreground remains"),
    ];
    driver.stack.last_mut().unwrap().history = foreground_history.clone();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                shrink: Some(cold_ready_test_shrink(vec![Message::user("stale shrink")])),
                ..single_noninteractive_completion("task-single", "single report")
            },
            &tx,
            false,
        )
        .await
        .unwrap();
    drop(tx);
    while rx.recv().await.is_some() {}

    assert_eq!(tool_result_id(&result), "task-single");
    assert_eq!(tool_result_text(&result), "single report");
    assert_eq!(driver.stack.last().unwrap().history, foreground_history);
}

#[tokio::test]
async fn noninteractive_single_inline_result_shape_is_unchanged() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single".to_string(),
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: None,
                repair_notes: Vec::new(),
                child_routing: None,
            },
            &tx,
            true,
        )
        .await
        .unwrap();
    drop(tx);
    while rx.recv().await.is_some() {}

    assert_eq!(tool_result_id(&result), "task-single");
    assert_eq!(tool_result_text(&result), "single report");
}

#[tokio::test]
async fn noninteractive_single_report_body_matches_live_event_db_event_row_and_result() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-single", "default");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single".to_string(),
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: Some(pending_test_shrink()),
                repair_notes: Vec::new(),
                child_routing: None,
            },
            &tx,
            true,
        )
        .await
        .unwrap();
    drop(tx);

    let mut live_report = None;
    while let Some(event) = rx.recv().await {
        if let TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            ..
        } = event
        {
            live_report = Some((agent, task_call_id, label, report));
        }
    }
    let (agent, task_call_id, label, report) = live_report.expect("live subagent report event");
    assert_eq!(agent, "explore");
    assert_eq!(task_call_id, "task-single");
    assert_eq!(label, "default");
    assert_eq!(report, "single report");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let event = events
        .iter()
        .find(|event| {
            event.kind == "subagent_report" && event.call_id.as_deref() == Some("task-single")
        })
        .expect("durable subagent_report event");
    assert_eq!(event.data["child_agent"], "explore");
    assert_eq!(event.data["task_call_id"], "task-single");
    assert_eq!(event.data["label"], "default");
    assert_eq!(event.data["report"], "single report");
    assert_eq!(event.data["provider_call_id"], "fn-single");
    assert_eq!(event.data["provider_call_id_source"], "provider");
    assert_eq!(
        event.data["provider_identity"]["provider_call_id"],
        "fn-single"
    );

    let row = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .unwrap()
        .into_iter()
        .find(|row| row.task_call_id == "task-single" && row.label == "default")
        .expect("completed task delegation child row");
    assert_eq!(row.child_agent, "explore");
    assert_eq!(row.report.as_deref(), Some("single report"));

    assert_eq!(tool_result_id(&result), "task-single");
    assert_eq!(tool_result_text(&result), "single report");
}

#[tokio::test]
async fn noninteractive_report_stamps_child_model() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-single-child-report", "default");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single-child-report".to_string(),
                task_function_call_id: Some("fn-single-child-report".to_string()),
                report: "single report".to_string(),
                failed: false,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: Some(pending_test_shrink()),
                repair_notes: Vec::new(),
                child_routing: Some(child_routing_for("child-report")),
            },
            &tx,
            true,
        )
        .await
        .unwrap();

    assert_eq!(tool_result_id(&result), "task-single-child-report");
    let events = drain_turn_events(&mut rx);
    let live_report = events
        .iter()
        .find_map(|event| match event {
            TurnEvent::SubagentReport {
                task_call_id,
                routing,
                ..
            } if task_call_id == "task-single-child-report" => Some(routing),
            _ => None,
        })
        .expect("live subagent_report event");
    assert_eq!(live_report["resolved_model"], "child-report");
    assert_ne!(live_report["resolved_model"], "local");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let event = events
        .iter()
        .find(|event| {
            event.kind == "subagent_report"
                && event.call_id.as_deref() == Some("task-single-child-report")
        })
        .expect("durable subagent_report event");
    assert_eq!(event.data["model"], "child-report");
    assert_eq!(event.data["routing"]["resolved_model"], "child-report");
    assert_ne!(event.data["routing"]["resolved_model"], "local");
}

#[tokio::test]
async fn noninteractive_batch_report_stamps_child_model() {
    let (mut driver, _tmp) = test_driver(8);
    write_delegated_model_config(&driver, &["local", "batch-child-report"]);
    seed_batch_task_delegation(&driver, "task-batch-child-report", &["first"]);
    seed_task_payload(&driver, "task-batch-child-report", "first", "explore");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    let task = BatchNoninteractiveTask {
        entries: vec![batch_entry(
            "first",
            "explore",
            Some(exact_model_selector("batch-child-report")),
        )],
        child_cwds: vec![root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-batch-child-report".to_string(),
        task_function_call_id: Some("fn-task-batch-child-report".to_string()),
    };

    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(completion.children.len(), 1);
    let events = drain_turn_events(&mut rx);
    let live_report = events
        .iter()
        .find_map(|event| match event {
            TurnEvent::SubagentReport {
                task_call_id,
                label,
                routing,
                ..
            } if task_call_id == "task-batch-child-report" && label == "first" => Some(routing),
            _ => None,
        })
        .expect("live batch subagent_report event");
    assert_eq!(live_report["resolved_model"], "batch-child-report");
    assert_ne!(live_report["resolved_model"], "local");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let event = events
        .iter()
        .find(|event| {
            event.kind == "subagent_report"
                && event.call_id.as_deref() == Some("task-batch-child-report")
                && event.data["label"] == "first"
        })
        .expect("durable batch subagent_report event");
    assert_eq!(event.data["model"], "batch-child-report");
    assert_eq!(
        event.data["routing"]["resolved_model"],
        "batch-child-report"
    );
    assert_ne!(event.data["routing"]["resolved_model"], "local");
}

#[tokio::test]
async fn docs_pipeline_emits_no_routing_amend() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-docs-routing", "default");
    seed_task_payload(&driver, "task-docs-routing", "default", "docs");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(128);
    let completion = driver
        .execute_single_noninteractive_task(
            single_task(
                &driver,
                "docs",
                "task-docs-routing",
                Some(exact_model_selector("docs-child")),
                Some("stale-docs-handle"),
            ),
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    driver
        .finalize_single_noninteractive_task(completion, &tx, true)
        .await
        .unwrap();

    let events = drain_turn_events(&mut rx);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TurnEvent::SubagentSpawned { task_call_id, .. } if task_call_id == "task-docs-routing"))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TurnEvent::SubagentRouting { task_call_id, .. } if task_call_id == "task-docs-routing"))
            .count(),
        0
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TurnEvent::SubagentReport { task_call_id, .. } if task_call_id == "task-docs-routing"))
            .count(),
        1
    );
}

#[tokio::test]
async fn spawn_load_failure_emits_no_amend_but_still_reports() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-load-failure", "default");
    seed_task_payload(&driver, "task-load-failure", "default", "missing-agent");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(128);
    let completion = driver
        .execute_single_noninteractive_task(
            single_task(
                &driver,
                "missing-agent",
                "task-load-failure",
                Some(exact_model_selector("missing-child")),
                None,
            ),
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(completion.failed);
    driver
        .finalize_single_noninteractive_task(completion, &tx, true)
        .await
        .unwrap();

    let events = drain_turn_events(&mut rx);
    let spawn_idx = events
        .iter()
        .position(|event| matches!(event, TurnEvent::SubagentSpawned { task_call_id, .. } if task_call_id == "task-load-failure"))
        .expect("spawn event");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::SubagentRouting { task_call_id, .. } if task_call_id == "task-load-failure"))
    );
    let report_idx = events
        .iter()
        .position(|event| matches!(event, TurnEvent::SubagentReport { task_call_id, .. } if task_call_id == "task-load-failure"))
        .expect("report event");
    assert!(spawn_idx < report_idx);
}

#[tokio::test]
async fn noninteractive_single_result_includes_task_repair_notes() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single".to_string(),
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: None,
                repair_notes: vec![
                    "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
                        .to_string(),
                ],
                child_routing: None,
            },
            &tx,
            true,
        )
        .await
        .unwrap();
    drop(tx);
    while rx.recv().await.is_some() {}

    let text = tool_result_text(&result);
    assert!(text.starts_with("dropped `action`"), "{text}");
    assert!(text.contains("\n\nsingle report"), "{text}");
}

#[tokio::test]
async fn noninteractive_batch_inline_result_shape_is_unchanged() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_batch_noninteractive_task(
            BatchNoninteractiveCompletion {
                task_call_id: "task-batch".to_string(),
                task_function_call_id: Some("fn-batch".to_string()),
                children: vec![
                    BatchChildCompletion {
                        idx: 1,
                        label: "second".to_string(),
                        child_agent: "reviewer".to_string(),
                        report: "second report".to_string(),
                        failed: false,
                        partial_progress: DelegationPartialProgress::default(),
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                    },
                    BatchChildCompletion {
                        idx: 0,
                        label: "first".to_string(),
                        child_agent: "explore".to_string(),
                        report: "Error: first issue was fixed".to_string(),
                        failed: false,
                        partial_progress: DelegationPartialProgress::default(),
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                    },
                ],
                repair_notes: Vec::new(),
            },
            &tx,
        )
        .await;
    drop(tx);
    while rx.recv().await.is_some() {}

    assert_eq!(tool_result_id(&result), "task-batch");
    let body: serde_json::Value = serde_json::from_str(&tool_result_text(&result)).unwrap();
    assert_eq!(body["status"], "completed");
    let children = body["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0]["label"], "first");
    assert_eq!(children[0]["agent"], "explore");
    assert_eq!(children[0]["failed"], false);
    assert_eq!(children[0]["report"], "Error: first issue was fixed");
    assert_eq!(children[1]["label"], "second");
    assert_eq!(children[1]["agent"], "reviewer");
    assert_eq!(children[1]["failed"], false);
    assert_eq!(children[1]["report"], "second report");
}

#[tokio::test]
async fn noninteractive_batch_result_includes_task_repair_notes() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_batch_noninteractive_task(
            BatchNoninteractiveCompletion {
                task_call_id: "task-batch".to_string(),
                task_function_call_id: Some("fn-batch".to_string()),
                children: vec![BatchChildCompletion {
                    idx: 0,
                    label: "first".to_string(),
                    child_agent: "explore".to_string(),
                    report: "first report".to_string(),
                    failed: false,
                    partial_progress: DelegationPartialProgress::default(),
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                }],
                repair_notes: vec![
                    "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
                        .to_string(),
                ],
            },
            &tx,
        )
        .await;
    drop(tx);
    while rx.recv().await.is_some() {}

    let body: serde_json::Value = serde_json::from_str(&tool_result_text(&result)).unwrap();
    assert_eq!(
        body["repair_notes"][0],
        "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
    );
}

#[test]
fn queued_user_input_backgrounds_running_single_delegation() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-single",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("parent snapshot")]),
    );

    assert!(registry.background_on_user_input("task-single", "default"));
    assert_eq!(
        registry.status("task-single", "default"),
        Some(NoninteractiveDelegationStatus::Backgrounded)
    );
    assert_eq!(
        registry.child_agent("task-single", "default"),
        Some("explore")
    );
    assert_eq!(registry.snapshot_len("task-single", "default"), Some(1));
    assert!(
        !registry.background_on_user_input("task-single", "default"),
        "a backgrounded delegation is not backgrounded twice"
    );
}

#[test]
fn queued_user_input_backgrounds_running_batch_delegation() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-batch",
        "first",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("parent snapshot")]),
    );

    assert!(registry.background_on_user_input("task-batch", "first"));
    assert_eq!(
        registry.status("task-batch", "first"),
        Some(NoninteractiveDelegationStatus::Backgrounded)
    );
    assert_eq!(registry.child_agent("task-batch", "first"), Some("explore"));
}

#[test]
fn noninteractive_registry_is_live_only_for_running_and_backgrounded() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    assert!(!registry.is_live("task-1", "default"));
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.is_live("task-1", "default"));
    assert!(registry.background_on_user_input("task-1", "default"));
    assert!(registry.is_live("task-1", "default"));
    assert!(registry.cancel("task-1", "default"));
    assert!(!registry.is_live("task-1", "default"));

    registry.register_running(
        "task-2",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.complete("task-2", "default", "done".to_string(), false, None));
    assert!(!registry.is_live("task-2", "default"));
}

#[test]
fn noninteractive_registry_completion_status_uses_host_flag() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );

    assert!(registry.complete(
        "task-1",
        "default",
        "Error: quoted issue was fixed".to_string(),
        false,
        None,
    ));
    assert_eq!(
        registry.status("task-1", "default"),
        Some(NoninteractiveDelegationStatus::Completed)
    );

    registry.register_running(
        "task-2",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.complete(
        "task-2",
        "default",
        "ordinary report".to_string(),
        true,
        None
    ));
    assert_eq!(
        registry.status("task-2", "default"),
        Some(NoninteractiveDelegationStatus::Failed)
    );
}

#[test]
fn host_failure_sentinel_matches_only_host_error_shape() {
    assert!(is_host_failure_sentinel("Error: boom"));
    assert!(is_host_failure_sentinel("  Error: leading ws"));
    assert!(!is_host_failure_sentinel("Error:nospace"));
    assert!(!is_host_failure_sentinel("## Accomplished\nError: quoted"));
}

#[test]
fn task_control_orphan_list_status_cancel_and_refuse_live_actions() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-orphan", "default");

    let list = driver.dispatch_task_control(TaskControlAction::List, None, None, None);
    let list_json: serde_json::Value = serde_json::from_str(&list).unwrap();
    assert_eq!(list_json["type"], "task_delegation");
    assert_eq!(list_json["version"], 1);
    assert_eq!(list_json["state"], "list");
    assert_eq!(list_json["children"][0]["status"], "lost");
    assert_eq!(list_json["children"][0]["blocking"], false);
    assert_eq!(list_json["children"][0]["tool_call_closed"], false);
    assert_eq!(list_json["children"][0]["result_pending"], true);
    assert_eq!(list_json["children"][0]["report_available"], false);
    assert_eq!(list_json["children"][0]["report_delivered"], false);
    assert_eq!(list_json["children"][0]["pending_steers"], 0);
    assert_eq!(list_json["children"][0]["orphaned"], true);
    assert_eq!(list_json["children"][0]["actionable"], false);

    let status = driver.dispatch_task_control(
        TaskControlAction::Status,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        None,
    );
    let status_json: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status_json["state"], "status");
    assert_eq!(status_json["children"][0]["status"], "lost");
    assert_eq!(status_json["children"][0]["orphaned"], true);

    let query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        None,
    );
    let query_json: serde_json::Value = serde_json::from_str(&query).unwrap();
    assert_eq!(query_json["state"], "refused");
    assert_eq!(query_json["actionable"], false);
    assert_eq!(
        query_json["reason"],
        "lost (daemon restarted; no live worker)"
    );
    assert_eq!(query_json["report_source"], "none");
    assert_eq!(query_json["children"][0]["status"], "lost");

    let steer = driver.dispatch_task_control(
        TaskControlAction::Steer,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        Some("please continue".to_string()),
    );
    let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
    assert_eq!(steer_json["state"], "refused");
    assert_eq!(steer_json["actionable"], false);
    assert_eq!(
        steer_json["reason"],
        "lost (daemon restarted; no live worker)"
    );
    assert_eq!(steer_json["children"][0]["status"], "lost");

    let cancel = driver.dispatch_task_control(
        TaskControlAction::Cancel,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        None,
    );
    let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
    assert_eq!(cancel_json["state"], "lost");
    assert_eq!(cancel_json["cancelled"].as_array().unwrap().len(), 0);
    assert_eq!(cancel_json["orphaned_lost"][0], "task-orphan:default");
    let rows = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .unwrap();
    assert_eq!(
        rows[0].status,
        crate::db::task_delegations::DelegationStatus::Lost
    );
}

#[test]
fn task_control_live_registry_entry_keeps_happy_path() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-live", "default");
    driver.noninteractive_delegations.register_running(
        "task-live",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live context")]),
    );

    let list = driver.dispatch_task_control(TaskControlAction::List, None, None, None);
    let list_json: serde_json::Value = serde_json::from_str(&list).unwrap();
    assert_eq!(list_json["state"], "list");
    assert_eq!(list_json["children"][0]["status"], "running");
    assert_eq!(list_json["children"][0]["blocking"], true);
    assert_eq!(list_json["children"][0]["tool_call_closed"], false);
    assert_eq!(list_json["children"][0]["result_pending"], false);
    assert_eq!(list_json["children"][0]["report_available"], false);
    assert_eq!(list_json["children"][0]["report_delivered"], false);
    assert_eq!(list_json["children"][0]["pending_steers"], 0);
    assert_eq!(list_json["children"][0]["orphaned"], false);
    assert_eq!(list_json["children"][0]["actionable"], true);

    let query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-live".to_string()),
        Some("default".to_string()),
        None,
    );
    let query_json: serde_json::Value = serde_json::from_str(&query).unwrap();
    assert_eq!(query_json["state"], "query");
    assert_eq!(query_json["task_call_id"], "task-live");
    assert_eq!(query_json["read_only"], true);
    assert_eq!(query_json["child_state_unchanged"], true);
    assert_eq!(query_json["report_source"], "live_snapshot");
    assert!(
        query_json["report"]
            .as_str()
            .unwrap()
            .contains("live context"),
        "{query_json}"
    );
    assert_eq!(query_json["children"][0]["status"], "running");

    let steer = driver.dispatch_task_control(
        TaskControlAction::Steer,
        Some("task-live".to_string()),
        Some("default".to_string()),
        Some("keep going".to_string()),
    );
    let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
    assert_eq!(steer_json["state"], "steer_queued");
    assert_eq!(steer_json["applies_at"], "next_child_turn_boundary");
    assert_eq!(steer_json["applies_if"], "child_still_running_actionable");
    assert_eq!(steer_json["children"][0]["pending_steers"], 1);

    let cancel = driver.dispatch_task_control(
        TaskControlAction::Cancel,
        Some("task-live".to_string()),
        Some("default".to_string()),
        None,
    );
    let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
    assert_eq!(cancel_json["state"], "cancelled");
    assert_eq!(cancel_json["cancelled"][0], "task-live:default");
    let rows = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .unwrap();
    assert_eq!(
        rows[0].status,
        crate::db::task_delegations::DelegationStatus::Cancelled
    );
}

#[test]
fn task_query_reports_db_and_none_sources() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-db", "default");
    driver
        .session
        .db
        .write_blocking(move |conn| {
            conn.execute(
                "UPDATE task_delegation_children SET report = 'db report' WHERE task_call_id = 'task-db' AND label = 'default'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    driver.noninteractive_delegations.register_running(
        "task-db",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live fallback")]),
    );

    let db_query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-db".to_string()),
        Some("default".to_string()),
        None,
    );
    let db_json: serde_json::Value = serde_json::from_str(&db_query).unwrap();
    assert_eq!(db_json["state"], "query");
    assert_eq!(db_json["report_source"], "db");
    assert_eq!(db_json["report"], "db report");
    assert_eq!(db_json["report_available"], true);

    seed_task_delegation(&driver, "task-none", "default");
    driver.noninteractive_delegations.register_running(
        "task-none",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    let none_query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-none".to_string()),
        Some("default".to_string()),
        None,
    );
    let none_json: serde_json::Value = serde_json::from_str(&none_query).unwrap();
    assert_eq!(none_json["state"], "query");
    assert_eq!(none_json["report_source"], "none");
    assert_eq!(none_json["report_available"], false);
    assert!(
        none_json["report"]
            .as_str()
            .unwrap()
            .contains("No report yet")
    );
}

#[test]
fn late_noninteractive_completion_delivers_once() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.background_on_user_input("task-1", "default"));

    let result = Message::tool_result_with_call_id("task-1".to_string(), None, "done".to_string());
    assert!(registry.complete("task-1", "default", "done".to_string(), false, Some(result)));
    assert!(
        !registry.complete(
            "task-1",
            "default",
            "duplicate".to_string(),
            false,
            Some(Message::tool_result_with_call_id(
                "task-1".to_string(),
                None,
                "duplicate".to_string(),
            ))
        ),
        "completion is accepted exactly once"
    );

    let delivered = registry
        .take_late_result("task-1", "default")
        .expect("first late result");
    assert_eq!(tool_result_text(&delivered), "done");
    assert!(
        registry.take_late_result("task-1", "default").is_none(),
        "late result is delivered exactly once"
    );
}

#[test]
fn background_ack_is_small_deterministic_and_omits_original_prompt() {
    let completed = vec![("first".to_string(), "first report".to_string())];
    let running = vec!["second".to_string()];
    let body = format_delegation_background_ack("task-batch", &completed, &running);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "backgrounded");
    assert_eq!(json["task_call_id"], "task-batch");
    assert_eq!(json["blocking"], false);
    assert_eq!(json["tool_call_closed"], true);
    assert_eq!(json["result_pending"], true);
    let children = json["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0]["task_call_id"], "task-batch");
    assert_eq!(children[0]["label"], "first");
    assert_eq!(children[0]["status"], "completed");
    assert_eq!(children[0]["newly_delivered"], true);
    assert_eq!(children[0]["report"], "first report");
    assert_eq!(children[1]["task_call_id"], "task-batch");
    assert_eq!(children[1]["label"], "second");
    assert_eq!(children[1]["status"], "backgrounded");
    assert_eq!(children[1]["result_pending"], true);
    assert!(!body.contains("original child prompt"));
}

#[test]
fn async_delegation_result_lists_only_new_children_with_status() {
    let completed = vec![
        AsyncDelegationChildResult {
            label: "second".to_string(),
            status: "completed".to_string(),
            report: Some("second report".to_string()),
        },
        AsyncDelegationChildResult {
            label: "third".to_string(),
            status: "failed".to_string(),
            report: Some("third failed".to_string()),
        },
    ];
    let running = Vec::new();
    let body = format_async_delegation_result("task-batch", &completed, &running);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "failed");
    assert_eq!(json["task_call_id"], "task-batch");
    assert_eq!(json["result_pending"], false);
    let children = json["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0]["task_call_id"], "task-batch");
    assert_eq!(children[0]["label"], "second");
    assert_eq!(children[0]["status"], "completed");
    assert_eq!(children[0]["newly_delivered"], true);
    assert_eq!(children[0]["report"], "second report");
    assert_eq!(children[1]["task_call_id"], "task-batch");
    assert_eq!(children[1]["label"], "third");
    assert_eq!(children[1]["status"], "failed");
    assert_eq!(children[1]["error"], "third failed");
    assert!(!body.contains("first report"));
}

/// An async-result delivery header names both the job `kind` and the
/// originating `job_id` (implementation note), identically
/// across every job kind (`loop`/`timer`/`background`/`swarm`). Drives the
/// real `ScheduleKind::as_str` so a kind-vocabulary drift is caught.
#[test]
fn async_result_header_names_kind_and_job_id_for_every_kind() {
    use crate::engine::schedule::spec::ScheduleKind;
    let job_id = "sched-f36b81df";
    for kind in [
        ScheduleKind::Loop,
        ScheduleKind::Timer,
        ScheduleKind::Background,
        ScheduleKind::Swarm,
    ] {
        let header = async_result_header(kind.as_str(), job_id);
        assert_eq!(
            header,
            format!("[async result · {} · sched-f36b81df]", kind.as_str()),
        );
    }
}

/// The recorded delivery event carries `data.job_id` set to the
/// originating id, additively alongside `text`
/// (implementation note). Round-trips through the real DB
/// serialization so the exported `events.json` shape is what's asserted.
/// Ordinary input (no job) omits the key entirely.
#[test]
fn delivery_event_data_carries_job_id_round_trip() {
    let (driver, _t) = test_driver(1);
    let session = driver.session.clone();

    // Async-result delivery: `data.job_id` present.
    let delivery = user_message_event_data(
        "[async result · loop · sched-abc]\nok",
        None,
        &[],
        Some("sched-abc"),
        &[],
        None,
        None,
    );
    session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &delivery,
        )
        .unwrap();
    // Ordinary user input: no `job_id` key.
    let ordinary = user_message_event_data("hello", None, &[], None, &[], None, None);
    assert!(
        ordinary.get("job_id").is_none(),
        "ordinary input must omit data.job_id: {ordinary}"
    );
    session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &ordinary,
        )
        .unwrap();

    let events = session.db.list_session_events(session.id).unwrap();
    let delivery_row = events
        .iter()
        .find(|e| e.data.get("job_id").is_some())
        .expect("delivery event with data.job_id persisted");
    assert_eq!(
        delivery_row.data.get("job_id").and_then(|v| v.as_str()),
        Some("sched-abc"),
    );
    // The text field still rides alongside, unchanged.
    assert_eq!(
        delivery_row.data.get("text").and_then(|v| v.as_str()),
        Some("[async result · loop · sched-abc]\nok"),
    );
    // Exactly one event carries the key — the ordinary message has none.
    assert_eq!(
        events
            .iter()
            .filter(|e| e.data.get("job_id").is_some())
            .count(),
        1,
    );
}
