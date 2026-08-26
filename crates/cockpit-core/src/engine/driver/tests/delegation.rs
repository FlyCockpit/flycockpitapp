use super::*;
use std::ops::ControlFlow;

fn task_tool_call_with_args(
    call_id: &str,
    function_call_id: &str,
    args: serde_json::Value,
) -> crate::engine::message::ToolCall {
    crate::engine::message::ToolCall {
        id: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
        provider: rig::message::ProviderCallId::new(function_call_id.to_string()),
        function: rig::message::ToolFunction {
            name: "task".into(),
            arguments: args,
        },
        signature: None,
        additional_params: None,
    }
}

async fn dispatch_task_args(
    driver: &Driver,
    args: serde_json::Value,
) -> crate::engine::agent::TurnOutcome {
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let tc = task_tool_call_with_args("task-unknown-agent", "fn-task-unknown-agent", args);
    let outcome = crate::config::trust::scope_workspace_trust_policy(
        crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&driver.cwd).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        },
        crate::engine::agent::phase_10_dispatch_one_call(
            &driver.stack[0].agent,
            &driver.session,
            &driver.config,
            &tx,
            &tc,
            "task",
        ),
    )
    .await
    .unwrap();
    match outcome {
        ControlFlow::Break(outcome) => outcome,
        ControlFlow::Continue(()) => panic!("task dispatch must be structural"),
    }
}

fn outcome_tool_result_text(outcome: crate::engine::agent::TurnOutcome) -> String {
    match outcome {
        crate::engine::agent::TurnOutcome::ToolResult { body, .. } => body,
        _ => panic!("expected tool-result refusal"),
    }
}

fn write_test_agent(root: &std::path::Path, name: &str, _fork_eligible: bool) {
    let dir = root.join(".cockpit").join("agents");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.md")),
        format!(
            "---\ndescription: Test agent.\nschemaVersion: 2\nagentId: authored/{name}\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Execute a coding task\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\n\nTest prompt.\n"
        ),
    )
    .unwrap();
}

fn set_active_agent_name_and_mode(
    driver: &mut Driver,
    name: &str,
    mode: crate::config::extended::LlmMode,
) {
    let mut agent = (*driver.stack[0].agent).clone();
    agent.name = name.to_string();
    agent.llm_mode = mode;
    driver.stack[0].agent = std::sync::Arc::new(agent);
}

fn fork_delegate_args(agent: &str, prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "intent": "delegate",
        "payload": {
            "agent": agent,
            "prompt": prompt,
            "mode": "subagent",
            "context": "fork"
        }
    })
}

async fn fork_refusal_text(driver: &Driver, args: serde_json::Value) -> String {
    outcome_tool_result_text(dispatch_task_args(driver, args).await)
}

#[tokio::test]
async fn fork_rejected_when_child_differs_from_parent() {
    let (mut driver, tmp) = test_driver_without_network(8);
    write_test_agent(tmp.path(), "forker", true);
    set_active_agent_name_and_mode(
        &mut driver,
        "forker",
        crate::config::extended::LlmMode::Frontier,
    );

    let body = fork_refusal_text(&driver, fork_delegate_args("explore", "look")).await;

    assert!(
        body.contains("must target the delegating agent `forker`"),
        "{body}"
    );
}

#[tokio::test]
async fn fork_rejected_with_explicit_model_selector() {
    let (mut driver, tmp) = test_driver_without_network(8);
    write_test_agent(tmp.path(), "forker", true);
    set_active_agent_name_and_mode(
        &mut driver,
        "forker",
        crate::config::extended::LlmMode::Frontier,
    );
    let mut args = fork_delegate_args("forker", "look");
    args["payload"]["model"] = serde_json::json!({
        "kind": "exact",
        "selector": "lmstudio:local"
    });

    let body = fork_refusal_text(&driver, args).await;

    assert!(body.contains("cannot specify `model`"), "{body}");
}

#[tokio::test]
async fn fork_rejected_for_non_fork_eligible_agent() {
    let (mut driver, tmp) = test_driver_without_network(8);
    write_test_agent(tmp.path(), "forker", false);
    set_active_agent_name_and_mode(
        &mut driver,
        "forker",
        crate::config::extended::LlmMode::Frontier,
    );

    let body = fork_refusal_text(&driver, fork_delegate_args("forker", "look")).await;

    assert!(body.contains("is not fork eligible"), "{body}");
}

#[tokio::test]
async fn fork_rejected_in_non_frontier_mode() {
    let (mut driver, tmp) = test_driver_without_network(8);
    write_test_agent(tmp.path(), "forker", true);
    set_active_agent_name_and_mode(
        &mut driver,
        "forker",
        crate::config::extended::LlmMode::Normal,
    );

    let body = fork_refusal_text(&driver, fork_delegate_args("forker", "look")).await;

    assert!(body.contains("only available in frontier"), "{body}");
}

#[tokio::test]
async fn fork_rejected_for_interactive_delegation() {
    let (mut driver, tmp) = test_driver_without_network(8);
    write_test_agent(tmp.path(), "forker", true);
    set_active_agent_name_and_mode(
        &mut driver,
        "forker",
        crate::config::extended::LlmMode::Frontier,
    );
    let mut args = fork_delegate_args("forker", "look");
    args["payload"]["mode"] = serde_json::json!("subagent_interactive");

    let body = fork_refusal_text(&driver, args).await;

    assert!(body.contains("must resolve noninteractively"), "{body}");
}

#[tokio::test]
async fn fork_rejected_with_redundant_seed_tags() {
    let (mut driver, tmp) = test_driver_without_network(8);
    write_test_agent(tmp.path(), "forker", true);
    set_active_agent_name_and_mode(
        &mut driver,
        "forker",
        crate::config::extended::LlmMode::Frontier,
    );

    let body = fork_refusal_text(&driver, fork_delegate_args("forker", "read @src/lib.rs")).await;

    assert!(body.contains("remove @file/@dir/ and /skill"), "{body}");
}

#[tokio::test]
async fn vnext_agent_refuses_retired_fork_eligibility_contract() {
    let (mut driver, tmp) = test_driver_without_network(8);
    write_test_agent(tmp.path(), "forker", true);
    set_active_agent_name_and_mode(
        &mut driver,
        "forker",
        crate::config::extended::LlmMode::Frontier,
    );

    let body = fork_refusal_text(&driver, fork_delegate_args("forker", "steer")).await;
    assert!(body.contains("is not fork eligible"), "{body}");
}

#[tokio::test]
async fn unknown_context_value_defaults_to_fresh() {
    let (driver, _tmp) = test_driver_without_network(8);
    let outcome = dispatch_task_args(
        &driver,
        serde_json::json!({
            "intent": "delegate",
            "payload": {
                "agent": "explore",
                "prompt": "look",
                "mode": "subagent",
                "context": "mystery"
            }
        }),
    )
    .await;

    match outcome {
        crate::engine::agent::TurnOutcome::SpawnNoninteractive { context, .. } => {
            assert_eq!(context, crate::engine::agent::TaskContext::Fresh);
        }
        other => panic!("expected fresh noninteractive spawn, got {other:?}"),
    }
}

#[tokio::test]
async fn fork_child_seeds_from_parent_transcript() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    driver.stack[0].history = vec![
        Message::user("parent asks"),
        Message::assistant("parent answers"),
    ];

    let (_fork_session, history) = driver.prepare_fork_task_context().await.unwrap();

    assert_eq!(history.len(), 2);
    assert!(format!("{history:?}").contains("parent asks"));
    assert!(format!("{history:?}").contains("parent answers"));
}

#[tokio::test]
async fn fork_child_snapshot_independent_of_parent_drift() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    driver.stack[0].history = vec![Message::user("stable parent")];

    let (_fork_session, history) = driver.prepare_fork_task_context().await.unwrap();
    driver.stack[0].history.push(Message::user("late drift"));

    assert_eq!(history.len(), 1);
    assert!(format!("{history:?}").contains("stable parent"));
    assert!(!format!("{history:?}").contains("late drift"));
}

#[tokio::test]
async fn fork_of_empty_parent_yields_steering_only() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    driver.stack[0].history.clear();

    let (_fork_session, mut history) = driver.prepare_fork_task_context().await.unwrap();
    history.push(Message::user("steer only"));

    assert_eq!(history.len(), 1);
    assert!(format!("{history:?}").contains("steer only"));
}

#[tokio::test]
async fn fork_child_records_fork_ceiling() {
    let (driver, _tmp) = test_driver_without_network(8);
    let seq = driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "persisted parent"}),
        )
        .await
        .unwrap();

    let (fork_session, _history) = driver.prepare_fork_task_context().await.unwrap();

    assert_eq!(fork_session.parent_session_id, Some(driver.session.id));
    assert_eq!(fork_session.fork_point_turn_id, Some(seq.to_string()));
}

/// Subagent inheritance characterization: a real fork-context subagent
/// session created through the production delegation seam resolves a
/// parent sealed value written before the fork point, without exposing
/// the literal on metadata or event surfaces.
#[tokio::test]
async fn sealed_subagent_inherits_parent_value_before_fork_point() {
    let (driver, _tmp) = test_driver_without_network(8);
    // Distinct high-entropy literal kept out of assert_eq! failure output.
    let literal = "parent-pre-fork-sealed-value-9f3a";
    driver
        .session
        .set_sealed_value(
            crate::sealed::OwnerAuthority::for_test("owner"),
            &crate::redact::RedactionTable::empty(),
            "parent_pre",
            literal,
            "delegation inheritance",
            "user",
        )
        .await
        .unwrap();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "delegate after seal"}),
        )
        .await
        .unwrap();

    let (child, history) = driver.prepare_fork_task_context().await.unwrap();
    assert_eq!(child.parent_session_id, Some(driver.session.id));
    let history_dump = format!("{history:?}");
    assert!(
        !history_dump.contains(literal),
        "fork history (model-facing seed) must not carry the sealed literal"
    );

    assert!(
        child
            .sealed_value_exists(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "parent_pre"
            )
            .await
            .unwrap(),
        "subagent must inherit parent value sealed before fork point"
    );
    // Availability only — do not read the literal-bearing wrapper via as_str.
    // Prove the sealed literal is redacted and never appears on metadata/events.
    let parent_table = driver
        .session
        .persisted_redaction_table()
        .unwrap()
        .expect("parent redaction table");
    assert!(
        !parent_table.scrub(literal).contains(literal),
        "parent redaction table must scrub the sealed literal"
    );

    let child_meta = child
        .list_sealed_value_metadata(crate::sealed::OwnerAuthority::for_test("owner"))
        .await
        .unwrap();
    assert!(
        child_meta.iter().any(|row| row.value_id == "parent_pre"),
        "child metadata must list the inherited id"
    );
    for row in &child_meta {
        assert!(!row.value_id.contains(literal));
        assert!(!row.reason.contains(literal));
        assert!(!row.origin.contains(literal));
    }
    let child_events = child.db.list_session_events(child.id).await.unwrap();
    for event in &child_events {
        assert!(
            !event.data.to_string().contains(literal),
            "subagent event payload must not carry the sealed literal"
        );
    }
    let parent_meta = driver
        .session
        .list_sealed_value_metadata(crate::sealed::OwnerAuthority::for_test("owner"))
        .await
        .unwrap();
    for row in &parent_meta {
        assert!(!row.value_id.contains(literal));
        assert!(!row.reason.contains(literal));
        assert!(!row.origin.contains(literal));
    }
    let parent_events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    for event in &parent_events {
        assert!(
            !event.data.to_string().contains(literal),
            "parent event payload must not carry the sealed literal"
        );
    }
}

/// Late parent writes after the subagent fork must stay parent-only under
/// the existing fork-point snapshot contract.
#[tokio::test]
async fn sealed_subagent_does_not_inherit_late_parent_value() {
    let (driver, _tmp) = test_driver_without_network(8);
    let early = "parent-early-sealed-value-7c2b";
    let late = "parent-late-sealed-value-4e1d";
    driver
        .session
        .set_sealed_value(
            crate::sealed::OwnerAuthority::for_test("owner"),
            &crate::redact::RedactionTable::empty(),
            "early_token",
            early,
            "before fork",
            "user",
        )
        .await
        .unwrap();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "fork now"}),
        )
        .await
        .unwrap();

    let (child, _history) = driver.prepare_fork_task_context().await.unwrap();
    assert!(
        child
            .sealed_value_exists(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "early_token"
            )
            .await
            .unwrap(),
        "value sealed before fork remains injectable on the child"
    );

    let parent_table = driver.session.persisted_redaction_table().unwrap().unwrap();
    driver
        .session
        .set_sealed_value(
            crate::sealed::OwnerAuthority::for_test("owner"),
            &parent_table,
            "late_token",
            late,
            "after fork",
            "user",
        )
        .await
        .unwrap();

    assert!(
        driver
            .session
            .sealed_value_exists(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "late_token"
            )
            .await
            .unwrap(),
        "parent must resolve its own late value"
    );
    assert!(
        !child
            .sealed_value_exists(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "late_token"
            )
            .await
            .unwrap(),
        "subagent must not see parent values written after the fork point"
    );
    let child_meta = child
        .list_sealed_value_metadata(crate::sealed::OwnerAuthority::for_test("owner"))
        .await
        .unwrap();
    assert!(
        child_meta.iter().all(|row| row.value_id != "late_token"),
        "late parent id must not appear on the child metadata list"
    );
}

#[tokio::test]
async fn task_delegate_unknown_agent_refuses_with_reachable_list() {
    let (driver, _tmp) = test_driver(8);

    let body = outcome_tool_result_text(
        dispatch_task_args(
            &driver,
            serde_json::json!({
                "agent": "no-such-agent",
                "prompt": "do it"
            }),
        )
        .await,
    );

    assert!(
        body.contains("Error: unknown agent `no-such-agent`"),
        "{body}"
    );
    assert!(body.contains("Reachable agents from `Build`"), "{body}");
    assert!(body.contains("builder"), "{body}");
}

#[tokio::test]
async fn task_delegate_unknown_agent_writes_no_delegation_payload_row() {
    let (driver, _tmp) = test_driver(8);

    let _ = dispatch_task_args(
        &driver,
        serde_json::json!({
            "agent": "no-such-agent",
            "prompt": "do it"
        }),
    )
    .await;

    let children = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .await
        .unwrap();
    assert!(children.is_empty(), "{children:?}");
}

#[tokio::test]
async fn task_batch_unknown_agent_refuses_naming_the_label() {
    let (driver, _tmp) = test_driver(8);

    let body = outcome_tool_result_text(
        dispatch_task_args(
            &driver,
            serde_json::json!({
                "intent": "batch",
                "batch": [
                    {
                        "label": "bad-review",
                        "agent": "no-such-agent",
                        "prompt": "review it"
                    }
                ]
            }),
        )
        .await,
    );

    assert!(body.contains("batch entry `bad-review`"), "{body}");
    assert!(body.contains("unknown agent `no-such-agent`"), "{body}");
    assert!(body.contains("builder"), "{body}");
}

#[tokio::test]
async fn task_delegate_absent_agent_still_defaults_to_builder() {
    let (driver, _tmp) = test_driver(8);

    match dispatch_task_args(
        &driver,
        serde_json::json!({
            "intent": "delegate",
            "delegate": { "prompt": "do it" }
        }),
    )
    .await
    {
        crate::engine::agent::TurnOutcome::SpawnSubagent { child_agent, .. } => {
            assert_eq!(child_agent, "builder");
        }
        _ => panic!("absent agent should default to interactive builder delegation"),
    }
}

#[tokio::test]
async fn task_delegate_with_cwd_argument_defers_validation() {
    let (driver, tmp) = test_driver(8);
    let child_dir = tmp.path().join("child");
    std::fs::create_dir_all(&child_dir).unwrap();

    match dispatch_task_args(
        &driver,
        serde_json::json!({
            "intent": "delegate",
            "delegate": {
                "agent": "only-under-child",
                "prompt": "do it",
                "cwd": "child",
                "mode": "subagent"
            }
        }),
    )
    .await
    {
        crate::engine::agent::TurnOutcome::SpawnNoninteractive {
            child_agent, cwd, ..
        } => {
            assert_eq!(child_agent, "only-under-child");
            assert_eq!(cwd.as_deref(), Some("child"));
        }
        _ => panic!("cwd-scoped unknown agent should defer parse-time validation"),
    }
}

#[tokio::test]
async fn task_unknown_agent_records_tool_rejected_event() {
    let (driver, _tmp) = test_driver(8);

    let _ = dispatch_task_args(
        &driver,
        serde_json::json!({
            "agent": "no-such-agent",
            "prompt": "do it"
        }),
    )
    .await;

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let event = events
        .iter()
        .find(|event| event.kind == "tool_rejected")
        .expect("tool_rejected event");
    assert_eq!(event.data["tool"], "task");
    assert_eq!(event.data["reason"], "task_unknown_agent");
}

#[tokio::test]
async fn grant_rejection_unknown_agent_lists_reachable_agents() {
    let (driver, _tmp) = test_driver(8);

    let message = grant_rejection(GrantRejectionInput {
        parent_cwd: &driver.cwd,
        cwd: &driver.cwd,
        config: &driver.config,
        parent_agent: "Build",
        parent_vnext_grant: None,
        child_agent: "no-such-agent",
        grant: &[],
        assistant_db: &driver.session.db,
        local_installations: &driver.vnext_local_installation_resolver,
    })
    .await
    .unwrap();

    assert!(
        message.contains("Error: unknown agent `no-such-agent`"),
        "{message}"
    );
    assert!(
        message.contains("Reachable agents from `Build`"),
        "{message}"
    );
    assert!(message.contains("builder"), "{message}");
}

#[tokio::test]
async fn resolved_cwd_unknown_agent_refuses_before_load() {
    let (mut driver, tmp) = test_driver(8);
    let child_dir = tmp.path().join("child");
    std::fs::create_dir_all(&child_dir).unwrap();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let task = SingleNoninteractiveTask {
        child_agent: "only-under-child".to_string(),
        brief: "look around".to_string(),
        model: None,
        remaining_depth: Some(0),
        why: "test".to_string(),
        resume_handle: None,
        child_cwd: ChildCwd {
            requested: Some("child".to_string()),
            resolved: child_dir,
        },
        context: crate::engine::agent::TaskContext::Fresh,
        write_scope: None,
        granted_tools: Vec::new(),
        todo_ids: Vec::new(),
        child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        repair_notes: Vec::new(),
        task_call_id: "task-resolved-cwd".to_string(),
        task_provider_item_id: None,
        task_function_call_id: Some("fn-task-resolved-cwd".to_string()),
        recovery: None,
    };

    let completion = driver
        .execute_single_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();

    assert!(completion.failed);
    assert!(
        completion
            .report
            .contains("Error: unknown agent `only-under-child`"),
        "{}",
        completion.report
    );
    assert!(
        !completion.report.contains("failed to load"),
        "{}",
        completion.report
    );
    assert!(
        completion.report.contains("Reachable agents from `Build`"),
        "{}",
        completion.report
    );
}

#[test]
fn interactive_child_load_failure_returns_tool_error_without_pushing_child() {
    let (mut driver, tmp) = test_driver(8);
    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{"tools":{"read":{"enabled":true,"command":"echo hi"}}}"#,
    )
    .unwrap();
    driver.refresh_config_from_disk_for_tests();

    let message = match driver.load_interactive_child_or_tool_error(InteractiveChildLoadRequest {
        child_agent: "builder",
        granted_tools: Vec::new(),
        model: None,
        child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        task_call_id: "task-load-fail",
        task_provider_item_id: None,
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
            class: crate::engine::model::InferenceErrorClass::TimeoutTtft,
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
            class: crate::engine::model::InferenceErrorClass::Network,
            phase: "dispatch".into(),
        },
    ] {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
        let target = driver.active_queue_target();
        let mut accepted_ids = Vec::new();
        for text in ["first", "second"] {
            let (id, _) = queue
                .push(
                    UserSubmission {
                        expected_model_state_generation: None,
                        expected_model: None,
                        kind: UserSubmissionKind::User,
                        origin: Default::default(),
                        text: text.to_string(),
                        display_text: None,
                        tag_expansions: Vec::new(),
                        images: vec![],
                        forced_skill: None,
                        origin_principal: None,
                        job_id: None,
                        preflight_cleaned: None,
                        queue_item_ids: Vec::new(),
                        client_submissions: Vec::new(),
                        queue_target: None,
                        pending_terminal_disposition: None,
                        run_invocation_id: None,
                    },
                    target.clone(),
                )
                .await;
            accepted_ids.push(id);
        }

        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                driver.unwind_stack_to_root_and_discard_pending_input(reason, &queue, &tx),
            )
            .await
            .expect("cancel tombstones must become durable before releasing the queue"),
            2
        );
        let terminal_event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("durable cancellation must emit a correlated terminal event")
            .expect("terminal event channel remains open");
        assert!(
            matches!(
                terminal_event,
                TurnEvent::UserMessagesTerminated {
                    ref client_submission_ids,
                    disposition:
                        crate::daemon::proto::UserMessageTerminalDisposition::Cancelled,
                } if client_submission_ids == &accepted_ids
            ),
            "{terminal_event:?}"
        );
        let mut drained = Vec::new();
        queue
            .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
            .await;
        assert!(drained.is_empty());
        for id in accepted_ids {
            let terminal = driver
                .session
                .db
                .client_submission_terminal_receipt(driver.session.id, id)
                .await
                .unwrap()
                .expect("discarded accepted submission has a durable tombstone");
            assert_eq!(
                terminal.disposition,
                crate::db::session_log::ClientSubmissionTerminalDisposition::Cancelled
            );
            assert_eq!(terminal.fingerprint, id.to_string());
            assert_eq!(terminal.wire_fingerprint, id.to_string());
        }
    }
}

#[tokio::test]
async fn queued_user_fold_records_and_emits_stable_ids() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
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
        .expect("first queued message should persist")
        .expect("a queued message receives a durable sequence");
    let second_seq = driver
        .record_queued_user_fold(&drained[1], &tx)
        .await
        .expect("second queued message should persist")
        .expect("a queued message receives a durable sequence");

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
        .await
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
