use super::*;

#[tokio::test]
async fn intermediate_noninteractive_continue_checkpoint_survives_cancel_or_failure_for_restart() {
    // `history` and `next_prompt` model the state immediately after a turn
    // returned `Continue`: the tool result is ready for the next provider
    // round, but the late-steer continuation is not terminal yet. A crash or
    // nonterminal exit must retain that exact continuation identity so
    // recovery reattaches its permit instead of appending the user steer
    // payload to this saved prompt again.
    let continuation_id = uuid::Uuid::now_v7();
    let snapshot_json = ready_noninteractive_recovery_snapshot_with_late_steer(
        vec![Message::user("accepted steer's first provider handoff")],
        Message::user("tool result from the intermediate Continue round"),
        Some(continuation_id),
    )
    .unwrap();
    let recovered = parse_noninteractive_recovery_snapshot(&snapshot_json).unwrap();
    assert_eq!(
        recovered.late_user_steer_continuation_id,
        Some(continuation_id),
        "restart must wait for the exact accepted continuation rather than replaying its payload"
    );

    for outcome in [
        crate::engine::driver::LateUserSteerContinuationOutcome::Cancelled,
        crate::engine::driver::LateUserSteerContinuationOutcome::failed(
            "provider failed after an intermediate Continue",
        ),
    ] {
        let (respond_to, receipt) = tokio::sync::oneshot::channel();
        retain_noninteractive_late_steer_checkpoint(
            &[],
            vec![(
                uuid::Uuid::now_v7(),
                continuation_id,
                uuid::Uuid::now_v7(),
                "accepted late steer body".to_string(),
                respond_to,
            )],
            outcome.clone(),
        );
        assert_eq!(
            receipt.await.unwrap(),
            outcome,
            "a nonterminal Continue follow-up must retain—not complete—the accepted checkpoint"
        );
        assert_eq!(
            parse_noninteractive_recovery_snapshot(&snapshot_json)
                .unwrap()
                .late_user_steer_continuation_id,
            Some(continuation_id),
            "restart must continue to use the saved post-Continue checkpoint"
        );
    }
}

/// Workspace-authored v2 coding definition used by positive on-disk fixtures.
/// Tool authority deliberately stays out of these documents; tests that need a
/// constrained host surface write a `.tools.json` sidecar (see
/// [`write_host_tool_surface`]) instead of reviving `tools:`.
fn vnext_coding_agent_document(agent_id: &str, description: &str, body: &str) -> String {
    format!(
        "---\ndescription: {description}\nschemaVersion: 2\nagentId: authored/{agent_id}\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Execute the assigned coding task\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\n{body}\n"
    )
}

/// Host-projected tool grant for a workspace agent (test-only sidecar).
fn write_host_tool_surface(agents_dir: &std::path::Path, name: &str, tools: &[&str]) {
    std::fs::write(
        agents_dir.join(format!("{name}.tools.json")),
        serde_json::to_string(tools).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn child_failure_carries_structured_envelope_to_parent() {
    let fallback_tried = vec![crate::engine::agent::FailoverAttempt {
        provider: "flaky".to_string(),
        model: "primary".to_string(),
        error_class: Some(crate::engine::model::InferenceErrorClass::Network),
        outcome: "failed",
    }];
    let error = NoninteractiveRunError::new(
        anyhow::Error::new(crate::engine::model::InferenceFailure {
            provider: "flaky".to_string(),
            model: "primary".to_string(),
            phase: "dispatched".to_string(),
            class: crate::engine::model::InferenceErrorClass::Network,
            elapsed_ms: 37,
            retry_attempts: 3,
            detail: "connection refused".to_string(),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        }),
        Vec::new(),
        None,
        fallback_tried.clone(),
    );
    let (_message, _history, _fallback_decision, envelope) = error.into_parts();
    let envelope = envelope.expect("typed failure envelope");
    let outcome = DelegationChildOutcome::failed_with_envelope(
        envelope.clone(),
        DelegationPartialProgress::default(),
    );
    let carried = outcome.failure.expect("typed failure envelope");
    assert_eq!(carried.provider, "flaky");
    assert_eq!(carried.model, "primary");
    assert_eq!(
        carried.error_class,
        crate::engine::model::InferenceErrorClass::Network
    );
    assert_eq!(carried.elapsed_ms, 37);
    assert_eq!(carried.fallback_tried, fallback_tried);
    assert_eq!(carried.suggested_action, "retry_or_choose_another_model");
}

#[tokio::test]
async fn failover_walk_completes_before_parent_sees_envelope() {
    let fallback_tried = vec![
        crate::engine::agent::FailoverAttempt {
            provider: "dead".to_string(),
            model: "primary".to_string(),
            error_class: Some(crate::engine::model::InferenceErrorClass::TimeoutTtft),
            outcome: "failed",
        },
        crate::engine::agent::FailoverAttempt {
            provider: "dead2".to_string(),
            model: "backup".to_string(),
            error_class: Some(crate::engine::model::InferenceErrorClass::Http(500)),
            outcome: "failed",
        },
        crate::engine::agent::FailoverAttempt {
            provider: "healthy".to_string(),
            model: "fallback".to_string(),
            error_class: Some(crate::engine::model::InferenceErrorClass::TimeoutIdle),
            outcome: "failed",
        },
    ];
    let error = NoninteractiveRunError::new(
        anyhow::Error::new(crate::engine::model::InferenceFailure {
            provider: "healthy".to_string(),
            model: "fallback".to_string(),
            phase: "first_token".to_string(),
            class: crate::engine::model::InferenceErrorClass::TimeoutIdle,
            elapsed_ms: 120_000,
            retry_attempts: 1,
            detail: String::new(),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        }),
        Vec::new(),
        None,
        fallback_tried,
    );
    let (_message, _history, _fallback_decision, envelope) = error.into_parts();
    let envelope = envelope.expect("typed envelope");
    let outcome = DelegationChildOutcome::failed_with_envelope(
        envelope,
        DelegationPartialProgress::default(),
    );
    assert_eq!(
        outcome
            .failure
            .as_ref()
            .expect("typed envelope")
            .fallback_tried
            .len(),
        3
    );
}

#[tokio::test]
async fn child_routing_metadata_carries_fallback_chain() {
    let decision = crate::engine::agent::BackupFallbackDecision {
        primary_model: "primary".to_string(),
        error_class: crate::engine::model::InferenceErrorClass::TimeoutTtft,
        backup_model: "healthy".to_string(),
        fallback_tried: vec![
            crate::engine::agent::FailoverAttempt {
                provider: "dead".to_string(),
                model: "primary".to_string(),
                error_class: Some(crate::engine::model::InferenceErrorClass::TimeoutTtft),
                outcome: "failed",
            },
            crate::engine::agent::FailoverAttempt {
                provider: "healthy".to_string(),
                model: "healthy".to_string(),
                error_class: None,
                outcome: "succeeded",
            },
        ],
    };
    let routing = ChildRoutingMetadata {
        provider: "healthy".to_string(),
        model: "healthy".to_string(),
        model_trusted: true,
        routing: serde_json::json!({ "fallback_decision": "none" }),
    }
    .with_fallback_decision(Some(&decision));
    assert_eq!(routing.routing["fallback_decision"], "backup");
    assert_eq!(routing.routing["fallback_tried"][0]["model"], "primary");
    assert_eq!(routing.routing["fallback_tried"][1]["outcome"], "succeeded");
}

#[tokio::test]
async fn delegation_retry_budget_bounds_a_spinning_parent() {
    let (mut driver, _tmp) = test_driver(1);
    driver.reset_delegation_retry_budget();

    for _ in 0..DELEGATION_RETRY_BUDGET_PER_TURN {
        driver
            .consume_delegation_retry_budget()
            .expect("within budget");
    }

    let refusal = driver
        .consume_delegation_retry_budget()
        .expect_err("budget should reject the next task call");
    assert!(refusal.contains("budget exhausted"), "{refusal}");
    assert!(refusal.contains("task"), "{refusal}");
}

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

fn write_delegated_model_config(driver: &mut Driver, models: &[&str]) {
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
    // The driver now reads config through its snapshot handle, so refresh it
    // from the config just written (`engine-config-snapshot-adoption`).
    let cwd = driver.cwd.clone();
    driver.set_config_handle(
        crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(&cwd),
    );
}

fn failing_provider() -> cockpit_test_support::provider::ScriptedProvider {
    cockpit_test_support::provider::ScriptedProvider::builder()
        .turn(cockpit_test_support::provider::Turn::HttpError {
            status: 500,
            body: r#"{"error":{"message":"server failed"}}"#.into(),
        })
        .repeat_last()
        .start_blocking()
}

fn write_delegated_model_config_with_backup(
    driver: &mut Driver,
    primary_url: &str,
    backup_url: &str,
) {
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
    let cwd = driver.cwd.clone();
    driver.set_config_handle(
        crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(&cwd),
    );
}

async fn seed_task_payload(driver: &Driver, task_call_id: &str, label: &str, child_agent: &str) {
    driver
        .persist_delegation_payload(
            task_call_id,
            Some(&format!("fn-{task_call_id}")),
            "Build",
            label,
            child_agent,
            &format!("{label} prompt"),
        )
        .await
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
        context: crate::engine::agent::TaskContext::Fresh,
        write_scope: None,
        granted_tools: Vec::new(),
        todo_ids: Vec::new(),
        child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        repair_notes: Vec::new(),
        task_call_id: task_call_id.to_string(),
        task_provider_item_id: None,
        task_function_call_id: Some(format!("fn-{task_call_id}")),
        recovery: None,
    }
}

fn batch_entry(
    label: &str,
    child_agent: &str,
    model: Option<crate::engine::model_roles::DelegationModelSelector>,
) -> crate::engine::agent::BatchTaskEntry {
    crate::engine::agent::BatchTaskEntry {
        label: label.to_string(),
        depends_on: Vec::new(),
        child_agent: child_agent.to_string(),
        prompt: format!("{label} prompt"),
        model,
        remaining_depth: Some(0),
        resume_handle: None,
        cwd: None,
        context: crate::engine::agent::TaskContext::Fresh,
        granted_tools: Vec::new(),
        todo_ids: Vec::new(),
        write_scope: None,
    }
}

fn batch_entry_with_scope(
    label: &str,
    child_agent: &str,
    write_scope: &str,
) -> crate::engine::agent::BatchTaskEntry {
    let mut entry = batch_entry(label, child_agent, None);
    entry.write_scope = Some(write_scope.to_string());
    entry
}

fn set_root_scoped_parallel_write(driver: &mut Driver) {
    Arc::make_mut(&mut driver.stack[0].agent).posture =
        crate::agents::PostureResolution::from_grants(std::collections::BTreeSet::from([
            crate::agents::AgentCapability::ScopedParallelWrite,
        ]));
}

fn install_test_approver(driver: &mut Driver) -> Arc<crate::approval::Approver> {
    let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
    let store = crate::approval::store::GrantStore::new(
        driver.session.db.clone(),
        driver.session.id,
        driver.cwd.clone(),
        driver.config.clone(),
    );
    let approver = Arc::new(crate::approval::Approver::new(
        store,
        driver.session.db.clone(),
        driver.session.id,
        "Build",
        hub,
    ));
    driver.set_approver(approver.clone());
    approver
}

fn drain_turn_events(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn parallel_write_batch_refused_without_scoped_parallel_write() {
    let (driver, tmp) = test_driver(8);
    std::fs::create_dir_all(tmp.path().join("a")).unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let task = BatchNoninteractiveTask {
        entries: vec![batch_entry_with_scope("a", "builder", "a")],
        child_cwds: vec![root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-no-scoped-write".to_string(),
        task_provider_item_id: None,
        task_function_call_id: None,
    };

    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(completion.children.len(), 1);
    assert!(completion.children[0].failed);
    assert!(
        completion.children[0]
            .report
            .contains("scopedParallelWrite"),
        "{}",
        completion.children[0].report
    );
    assert!(
        drain_turn_events(&mut rx).is_empty(),
        "refused batch should not spawn child events"
    );

    let (mut driver, tmp) = test_driver(8);
    set_root_scoped_parallel_write(&mut driver);
    std::fs::create_dir_all(tmp.path().join("a")).unwrap();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let task = BatchNoninteractiveTask {
        entries: vec![batch_entry_with_scope("a", "builder", "a")],
        child_cwds: vec![root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-scoped-write".to_string(),
        task_provider_item_id: None,
        task_function_call_id: None,
    };
    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(completion.children.len(), 1);
    assert!(
        !completion.children[0]
            .report
            .contains("scopedParallelWrite"),
        "{}",
        completion.children[0].report
    );
}

#[tokio::test]
async fn overlapping_write_scopes_refuse_whole_batch() {
    let (mut driver, tmp) = test_driver(8);
    set_root_scoped_parallel_write(&mut driver);
    std::fs::create_dir_all(tmp.path().join("a/sub")).unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let task = BatchNoninteractiveTask {
        entries: vec![
            batch_entry_with_scope("left", "builder", "a"),
            batch_entry_with_scope("right", "builder", "a/sub"),
        ],
        child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-overlap".to_string(),
        task_provider_item_id: None,
        task_function_call_id: None,
    };

    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(completion.children.len(), 1);
    assert!(completion.children[0].failed);
    let report = &completion.children[0].report;
    assert!(report.contains("overlap"), "{report}");
    assert!(report.contains("left"), "{report}");
    assert!(report.contains("right"), "{report}");
    assert!(
        drain_turn_events(&mut rx).is_empty(),
        "refused batch should not spawn child events"
    );
}

#[tokio::test]
async fn write_scope_escaping_workspace_refused() {
    let (mut driver, tmp) = test_driver(8);
    set_root_scoped_parallel_write(&mut driver);
    let outside = tmp.path().parent().unwrap().join("outside-scope");
    std::fs::create_dir_all(&outside).unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let task = BatchNoninteractiveTask {
        entries: vec![batch_entry_with_scope(
            "escape",
            "builder",
            &outside.display().to_string(),
        )],
        child_cwds: vec![root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-escape".to_string(),
        task_provider_item_id: None,
        task_function_call_id: None,
    };

    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(completion.children.len(), 1);
    assert!(completion.children[0].failed);
    assert!(
        completion.children[0]
            .report
            .contains("outside the workspace"),
        "{}",
        completion.children[0].report
    );
    assert!(
        drain_turn_events(&mut rx).is_empty(),
        "refused batch should not spawn child events"
    );
}

#[tokio::test]
async fn write_capable_entry_requires_write_scope() {
    let (mut driver, _tmp) = test_driver(8);
    set_root_scoped_parallel_write(&mut driver);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let task = BatchNoninteractiveTask {
        entries: vec![batch_entry("missing", "builder", None)],
        child_cwds: vec![root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-missing-scope".to_string(),
        task_provider_item_id: None,
        task_function_call_id: None,
    };

    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(completion.children.len(), 1);
    assert!(completion.children[0].failed);
    assert!(
        completion.children[0]
            .report
            .contains("requires `write_scope`"),
        "{}",
        completion.children[0].report
    );
    assert!(
        drain_turn_events(&mut rx).is_empty(),
        "refused batch should not spawn child events"
    );
}

#[test]
fn scoped_child_subtree_is_pre_granted_read_write() {
    // The write-scope grant is DEFERRED to the child's dispatch point (AFTER its
    // post-build generation guard, so a generation move records no lingering
    // grant). The grant is recorded immediately BEFORE the child's first inference
    // request. On a big-stack thread (avoiding the pre-existing deep-batch stack
    // overflow) run the scoped `builder` against a long-delayed provider; once the
    // request is in flight the pregrant has already run, so poll the shared grant
    // store from THIS thread, then cancel before the 20s delay elapses.
    let provider = cockpit_test_support::provider::ScriptedProvider::builder()
        .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
        .turn(cockpit_test_support::provider::Turn::Text("done".into()))
        .with_delay(std::time::Duration::from_secs(20))
        .repeat_last()
        .start_blocking();
    let url = provider.base_url();
    let cancel = tokio_util::sync::CancellationToken::new();
    let batch_cancel = cancel.clone();
    let (handoff_tx, handoff_rx) = std::sync::mpsc::channel::<(
        std::sync::Arc<crate::approval::Approver>,
        std::path::PathBuf,
    )>();
    let batch_thread = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (mut driver, _tmp) = test_driver_with_url_vnext(8, url.clone());
                    let config_dir = driver.cwd.join(".cockpit");
                    let providers_dir = config_dir.join("providers");
                    std::fs::create_dir_all(&providers_dir).unwrap();
                    std::fs::write(
                        config_dir.join("config.json"),
                        r#"{"agent_chooses_subagent_model": true, "active_model": {"provider":"lmstudio","model":"local"}}"#,
                    )
                    .unwrap();
                    std::fs::write(
                        providers_dir.join("lmstudio.json"),
                        serde_json::json!({
                            "url": url,
                            "models": [{ "id": "local", "subagent_invokable": true }]
                        })
                        .to_string(),
                    )
                    .unwrap();
                    driver.refresh_config_from_disk_for_tests();
                    set_root_scoped_parallel_write(&mut driver);
                    let trust_cwd = driver.cwd.clone();
                    let _trust = crate::config::trust::enter_workspace_trust_policy(
                        crate::config::trust::WorkspaceTrustPolicy {
                            root: crate::config::trust::resolve_trust_root(&trust_cwd)
                                .unwrap_or_else(|_| crate::config::trust::TrustRoot {
                                    opened_path: trust_cwd.clone(),
                                    root: trust_cwd.clone(),
                                    kind: crate::config::trust::TrustRootKind::Directory,
                                }),
                            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                        },
                    );
                    let approver = install_test_approver(&mut driver);
                    let scope = driver.cwd.join("scope");
                    std::fs::create_dir_all(&scope).unwrap();
                    // Hand the shared approver + scope to the probing thread so it
                    // can poll the grant while this batch holds its guard.
                    handoff_tx.send((approver.clone(), scope.clone())).unwrap();
                    seed_batch_task_delegation(&driver, "task-pregrant", &["scoped"]).await;
                    seed_task_payload(&driver, "task-pregrant", "scoped", "builder").await;
                    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
                    let task = BatchNoninteractiveTask {
                        entries: vec![batch_entry_with_scope("scoped", "builder", "scope")],
                        child_cwds: vec![root_child_cwd(&driver)],
                        why: "test".to_string(),
                        repair_notes: Vec::new(),
                        task_call_id: "task-pregrant".to_string(),
                        task_provider_item_id: None,
                        task_function_call_id: None,
                    };
                    let _ = driver
                        .execute_batch_noninteractive_task(task, &tx, batch_cancel)
                        .await;
                })
        })
        .unwrap();

    let (approver, scope) = handoff_rx.recv().unwrap();
    // Wait for the child's inference request to reach the provider — the pregrant
    // is recorded immediately before it — then confirm the scoped subtree grant.
    let probe_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut granted = false;
    for _ in 0..200 {
        if provider.request_count() >= 1
            && probe_rt.block_on(approver.store().is_path_granted_for(
                &scope,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
            ))
        {
            granted = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    cancel.cancel();
    batch_thread.join().unwrap();
    assert!(
        granted,
        "a scoped child that dispatches has its subtree pre-granted read-write (recorded before its first request)"
    );
}

#[test]
fn scoped_child_holds_no_delegation_tools() {
    let (driver, tmp) = test_driver(8);
    let scope = tmp.path().join("scope");
    std::fs::create_dir_all(&scope).unwrap();
    let args = driver.spawn_args_delegated_in_cwd_scoped(
        tmp.path(),
        false,
        Vec::new(),
        None,
        crate::engine::builtin::DelegationRecursionContext::default(),
        DelegationConfinement {
            lock_identity: Some("builder#scoped".to_string()),
            write_scope: Some(scope),
        },
    );

    let child = crate::engine::builtin::load("builder", &args).unwrap();
    let names = child.tools.names();
    for tool in crate::agents::invariants::DELEGATION_TOOLS {
        assert!(
            !names.contains(tool),
            "scoped child unexpectedly held delegation tool `{tool}`"
        );
    }
}

fn child_routing_for(model: &str) -> ChildRoutingMetadata {
    ChildRoutingMetadata {
        provider: "lmstudio".to_string(),
        model: model.to_string(),
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
async fn noninteractive_display_delta_coalesces_typed_text() {
    use crate::engine::response_performance::AssistantAttemptId;

    let (child_tx, child_rx) = mpsc::channel(8);
    let (parent_tx, mut parent_rx) = mpsc::channel(8);
    let target = NoninteractiveSteerTarget::new("task-disp", "default");
    let forwarder = spawn_noninteractive_event_forwarder(child_rx, Some(parent_tx), Some(target));

    let attempt = AssistantAttemptId::new(42);
    child_tx
        .send(TurnEvent::AssistantDisplayTextDelta {
            agent: "Explore".into(),
            attempt_id: attempt,
            delta: "hel".into(),
        })
        .await
        .unwrap();
    child_tx
        .send(TurnEvent::AssistantDisplayTextDelta {
            agent: "Explore".into(),
            attempt_id: attempt,
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
        TurnEvent::NestedTurn { inner, .. } => match inner.as_ref() {
            TurnEvent::AssistantDisplayTextDelta {
                agent,
                attempt_id,
                delta,
            } => {
                assert_eq!(agent, "Explore");
                assert_eq!(*attempt_id, attempt);
                assert_eq!(delta, "hello");
            }
            other => panic!("expected coalesced display delta, got {other:?}"),
        },
        other => panic!("expected nested turn, got {other:?}"),
    }
    match parent_rx.recv().await.unwrap() {
        TurnEvent::NestedTurn { inner, .. } => {
            assert!(matches!(inner.as_ref(), TurnEvent::ToolStart { .. }));
        }
        other => panic!("expected nested tool start, got {other:?}"),
    }
    assert!(parent_rx.recv().await.is_none());
}

#[test]
fn noninteractive_single_spawn_amends_with_child_routing() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (mut driver, _tmp) = test_driver_vnext(8);
                    write_delegated_model_config(&mut driver, &["local", "child-single"]);
                    seed_task_delegation(&driver, "task-single-routing", "default").await;
                    seed_task_payload(&driver, "task-single-routing", "default", "explore").await;
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
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[tokio::test]
async fn delegated_child_succeeds_via_fallback_chain_and_export_records_it() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (mut driver, _tmp) = test_driver_vnext(8);
                    let primary_provider = failing_provider();
                    // Keep the provider alive for the delegation run; dropping it closes the listener.
                    let primary_url = primary_provider.base_url();
                    let backup_url = test_provider_base_url();
                    write_delegated_model_config_with_backup(
                        &mut driver,
                        &primary_url,
                        &backup_url,
                    );
                    seed_task_delegation(&driver, "task-single-fallback", "default").await;
                    seed_task_payload(&driver, "task-single-fallback", "default", "explore").await;
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
                    assert!(!completion.failed);
                    assert_eq!(routing.model, "child-flaky");
                    assert_eq!(routing.routing["fallback_decision"], "backup");
                    assert_eq!(routing.routing["fallback_tried"][0]["model"], "child-flaky");
                    assert_eq!(routing.routing["fallback_tried"][0]["outcome"], "failed");
                    assert_eq!(
                        routing.routing["fallback_tried"][1]["model"],
                        "backup-model"
                    );
                    assert_eq!(routing.routing["fallback_tried"][1]["outcome"], "succeeded");

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
                    assert_eq!(
                        routing_events[1]["fallback_tried"][0]["model"],
                        "child-flaky"
                    );
                    assert_eq!(
                        routing_events[1]["fallback_tried"][1]["model"],
                        "backup-model"
                    );

                    let _ = driver
                        .finalize_single_noninteractive_task(completion, &tx, true)
                        .await
                        .unwrap();
                    let report_event = driver
                        .session
                        .db
                        .list_session_events(driver.session.id)
                        .await
                        .unwrap()
                        .into_iter()
                        .find(|event| {
                            event.kind == "subagent_report"
                                && event.call_id.as_deref() == Some("task-single-fallback")
                        })
                        .expect("durable subagent_report event");
                    assert_eq!(report_event.data["routing"]["fallback_decision"], "backup");
                    assert_eq!(
                        report_event.data["routing"]["fallback_tried"][0]["model"],
                        "child-flaky"
                    );
                    assert_eq!(
                        report_event.data["routing"]["fallback_tried"][1]["outcome"],
                        "succeeded"
                    );
                });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[tokio::test]
async fn noninteractive_batch_spawn_amends_each_child_routing() {
    let (mut driver, _tmp) = test_driver_vnext(8);
    write_delegated_model_config(&mut driver, &["local", "child-first", "child-second"]);
    seed_batch_task_delegation(&driver, "task-batch-routing", &["first", "second"]).await;
    seed_task_payload(&driver, "task-batch-routing", "first", "explore").await;
    seed_task_payload(&driver, "task-batch-routing", "second", "scout").await;
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
        task_provider_item_id: None,
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
    let (mut driver, _tmp) = test_driver(8);
    write_delegated_model_config(&mut driver, &["local", "interactive-child"]);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let child = driver
        .load_interactive_child_or_tool_error(InteractiveChildLoadRequest {
            child_agent: "explore",
            granted_tools: Vec::new(),
            model: Some(exact_model_selector("interactive-child")),
            child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            task_call_id: "task-interactive-routing",
            task_provider_item_id: None,
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
        task_provider_item_id: None,
        task_function_call_id: Some("fn-task-a".to_string()),
        result: Box::new(Ok(single_noninteractive_completion("task-a", "a done"))),
    })
    .await
    .unwrap();
    tx.send(BackgroundNoninteractiveCompletion::Single {
        task_call_id: "task-b".to_string(),
        task_provider_item_id: None,
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
    seed_task_delegation(&driver, "task-lock", "default").await;
    driver.noninteractive_delegations.register_running(
        "task-lock",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver
        .locks
        .acquire(&path, "explore", driver.session.id)
        .await
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

    let body = driver
        .dispatch_task_control(
            TaskControlAction::Cancel,
            Some("task-lock".to_string()),
            None,
            None,
        )
        .await;

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
                task_provider_item_id: None,
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
async fn inline_completion_error_settles_child_failed_not_running() {
    // Regression: an inline (non-backgrounded) delegation whose spawned task
    // returns Err must settle its child to a terminal state in both the DB and
    // the registry. Previously only the backgrounded arm did this, so an inline
    // runtime failure left the child stuck `Running` and `task.control` reported
    // a dead child as running (a later steer/cancel could target a gone child).
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-inline-fail", "default").await;
    // Activate the child to `running` (a live status), as production does
    // before the child's task runs; settle only touches live children.
    driver
        .session
        .db
        .activate_task_delegation_children_with_snapshots(
            "task-inline-fail",
            vec![("default".to_string(), "{}".to_string())],
        )
        .await
        .unwrap();
    driver.noninteractive_delegations.register_running(
        "task-inline-fail",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    // No `background_on_user_input` → the job stays inline.
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-inline-fail".to_string(),
                task_provider_item_id: None,
                task_function_call_id: Some("fn-inline-fail".to_string()),
                result: Box::new(Err(anyhow::anyhow!("child crashed"))),
            }),
            &tx,
        )
        .await
        .unwrap();

    // The error is still returned inline as the tool result.
    assert!(matches!(
        delivery,
        NoninteractiveCompletionDelivery::Inline(_)
    ));

    // The inline error path now settles the live child: its registry entry is
    // no longer `Running`. Before the fix the inline arm settled nothing, so
    // the entry stayed `Running`. (The DB-row terminalization uses the same
    // `settle_task_tree_child` path as the backgrounded arm, which requires a
    // published AgentTree executor row that this driver-unit harness does not
    // build, so the registry settlement is what is asserted here.)
    assert_ne!(
        driver
            .noninteractive_delegations
            .status("task-inline-fail", "default"),
        Some(NoninteractiveDelegationStatus::Running),
        "inline delegation error left the child registry entry Running",
    );
}

#[tokio::test]
async fn backgrounded_completion_error_becomes_async_failed_result_once() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-bg-error", "default").await;
    driver
        .session
        .db
        .background_task_delegation_child("task-bg-error", "default")
        .await
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
                task_provider_item_id: None,
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
                task_provider_item_id: None,
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
    seed_batch_task_delegation(&driver, "task-mixed", &["first", "second", "third"]).await;
    for label in ["first", "second", "third"] {
        driver
            .session
            .db
            .background_task_delegation_child("task-mixed", label)
            .await
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
                task_provider_item_id: None,
                task_function_call_id: Some("fn-mixed".to_string()),
                result: Box::new(Ok(BatchNoninteractiveCompletion {
                    task_call_id: "task-mixed".to_string(),
                    task_provider_item_id: None,
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
                    already_terminal_labels: std::collections::BTreeSet::new(),
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
    seed_task_delegation(&driver, "task-single", "default").await;
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
                task_provider_item_id: None,
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                failure: None,
                partial_progress: DelegationPartialProgress::default(),
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
    seed_task_delegation(&driver, "task-single", "default").await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single".to_string(),
                task_provider_item_id: Some("fc_task_report_1".to_string()),
                task_function_call_id: Some("call_task_report_1".to_string()),
                report: "single report".to_string(),
                failed: false,
                failure: None,
                partial_progress: DelegationPartialProgress::default(),
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
        .await
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
    assert_eq!(event.data["provider_item_id"], "fc_task_report_1");
    assert_eq!(event.data["provider_call_id"], "call_task_report_1");
    assert_eq!(event.data["provider_call_id_source"], "provider");
    assert_eq!(
        event.data["provider_identity"]["provider_item_id"],
        "fc_task_report_1"
    );
    assert_eq!(
        event.data["provider_identity"]["provider_call_id"],
        "call_task_report_1"
    );

    let row = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.task_call_id == "task-single" && row.label == "default")
        .expect("completed task delegation child row");
    assert_eq!(row.child_agent, "explore");
    assert_eq!(row.report.as_deref(), Some("single report"));

    assert_eq!(tool_result_id(&result), "task-single");
    assert_eq!(tool_result_text(&result), "single report");
    assert_eq!(
        tool_result_provider_item_id(&result).as_deref(),
        Some("fc_task_report_1")
    );
    assert_eq!(
        tool_result_provider_call_id(&result).as_deref(),
        Some("call_task_report_1")
    );
}

#[tokio::test]
async fn noninteractive_report_stamps_child_model() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-single-child-report", "default").await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single-child-report".to_string(),
                task_provider_item_id: None,
                task_function_call_id: Some("fn-single-child-report".to_string()),
                report: "single report".to_string(),
                failed: false,
                failure: None,
                partial_progress: DelegationPartialProgress::default(),
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
        .await
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
    let (mut driver, _tmp) = test_driver_vnext(8);
    write_delegated_model_config(&mut driver, &["local", "batch-child-report"]);
    seed_batch_task_delegation(&driver, "task-batch-child-report", &["first"]).await;
    seed_task_payload(&driver, "task-batch-child-report", "first", "explore").await;
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
        task_provider_item_id: None,
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
        .await
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
    seed_task_delegation(&driver, "task-docs-routing", "default").await;
    seed_task_payload(&driver, "task-docs-routing", "default", "docs").await;
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

/// Run a batch of `[docs, readonly-probe]` against a long-delayed provider and
/// return how many child requests are in flight while the first is outstanding.
/// The docs entry runs its OWN pipeline (not `builtin::load`) under the EXCLUSIVE
/// write guard, so it can NEVER overlap the read-only-eligible sibling (which
/// takes a shared read guard) — exactly 1 in flight. If docs were wrongly admitted
/// concurrently (a shared read guard), BOTH would dispatch → 2. The batch runs on
/// a dedicated big-stack thread; the probe runs on THIS thread against the
/// provider's cross-thread atomic counter, then cancels so the 20s delay is never
/// fully waited.
fn dmh_docs_batch_exclusive_in_flight() -> usize {
    let provider = cockpit_test_support::provider::ScriptedProvider::builder()
        .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
        .turn(cockpit_test_support::provider::Turn::Text("done".into()))
        .with_delay(std::time::Duration::from_secs(20))
        .repeat_last()
        .start_blocking();
    let url = provider.base_url();
    let cancel = tokio_util::sync::CancellationToken::new();
    let batch_cancel = cancel.clone();
    let batch_thread = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (mut driver, _tmp) = test_driver_with_url(8, url.clone());
                    let config_dir = driver.cwd.join(".cockpit");
                    let providers_dir = config_dir.join("providers");
                    std::fs::create_dir_all(&providers_dir).unwrap();
                    // `web.provider = custom` (no commands) suppresses the default
                    // webfetch/websearch (Dynamic) so the read-only sibling is
                    // genuinely eligible for a shared read guard.
                    std::fs::write(
                        config_dir.join("config.json"),
                        r#"{"agent_chooses_subagent_model": true, "web": {"provider": "custom"}, "active_model": {"provider":"lmstudio","model":"local"}}"#,
                    )
                    .unwrap();
                    std::fs::write(
                        providers_dir.join("lmstudio.json"),
                        serde_json::json!({
                            "url": url,
                            "models": [{ "id": "local", "subagent_invokable": true }]
                        })
                        .to_string(),
                    )
                    .unwrap();
                    let agents_dir = config_dir.join("agents");
                    std::fs::create_dir_all(&agents_dir).unwrap();
                    std::fs::write(
                        agents_dir.join("readonly-probe.md"),
                        vnext_coding_agent_document(
                            "readonly-probe",
                            "read-only leaf",
                            "Investigate read-only.",
                        ),
                    )
                    .unwrap();
                    driver.refresh_config_from_disk_for_tests();
                    let trust_cwd = driver.cwd.clone();
                    let _trust = crate::config::trust::enter_workspace_trust_policy(
                        crate::config::trust::WorkspaceTrustPolicy {
                            root: crate::config::trust::resolve_trust_root(&trust_cwd)
                                .unwrap_or_else(|_| crate::config::trust::TrustRoot {
                                    opened_path: trust_cwd.clone(),
                                    root: trust_cwd.clone(),
                                    kind: crate::config::trust::TrustRootKind::Directory,
                                }),
                            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                        },
                    );
                    seed_batch_task_delegation(&driver, "task-docs-excl", &["docs", "probe"]).await;
                    seed_task_payload(&driver, "task-docs-excl", "docs", "docs").await;
                    seed_task_payload(&driver, "task-docs-excl", "probe", "readonly-probe").await;
                    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
                    let task = BatchNoninteractiveTask {
                        entries: vec![
                            batch_entry("docs", "docs", None),
                            batch_entry("probe", "readonly-probe", None),
                        ],
                        child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
                        why: "test".to_string(),
                        repair_notes: Vec::new(),
                        task_call_id: "task-docs-excl".to_string(),
                        task_provider_item_id: None,
                        task_function_call_id: None,
                    };
                    let _ = driver
                        .execute_batch_noninteractive_task(task, &tx, batch_cancel)
                        .await;
                })
        })
        .unwrap();

    for _ in 0..200 {
        if provider.request_count() >= 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let in_flight = provider.request_count();
    cancel.cancel();
    batch_thread.join().unwrap();
    in_flight
}

/// Fγ/Fiv: a `docs` batch entry runs its OWN 2-stage pipeline (the admission loop
/// must NOT `builtin::load("docs")`), reaching real inference — and it runs
/// EXCLUSIVELY: it never overlaps a read-only-eligible sibling. (Non-vacuous: a
/// wrongly-concurrent docs entry would overlap the sibling → 2 in flight.)
#[test]
fn batch_docs_entry_runs_exclusively() {
    assert_eq!(
        dmh_docs_batch_exclusive_in_flight(),
        1,
        "a docs batch entry runs its pipeline EXCLUSIVELY: it never overlaps the read-only sibling"
    );
}

/// Fii/Fiv: an unresolvable docs-stage model fails CLOSED with the content-safe
/// routing error — no panic, nothing dispatched. (`docs` is also not
/// surface-resolvable, so it is never concurrently admitted.)
#[tokio::test]
async fn batch_docs_entry_fails_closed_on_unresolvable_model() {
    let (mut driver, _tmp) = test_driver(8);
    dmh_install_config(
        &mut driver,
        serde_json::json!({}),
        vec![dmh_model("local", None)],
    );
    let cwd = driver.cwd.clone();
    // docs is not surface-resolvable (its stage name is rejected by `load`), so it
    // can never be admitted concurrently through the surface path.
    let probe_args = driver.spawn_args_delegated_in_cwd(
        &cwd,
        false,
        Vec::new(),
        None,
        crate::engine::builtin::DelegationRecursionContext::default(),
    );
    assert!(
        crate::engine::builtin::resolve_child_execution_surface("docs", &probe_args).is_err(),
        "docs is not surface-resolvable → never concurrently admitted"
    );

    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let task = BatchNoninteractiveTask {
        entries: vec![
            batch_entry(
                "docs-entry",
                "docs",
                Some(exact_model_selector("does-not-exist")),
            ),
            batch_entry("sib", "explore", None),
        ],
        child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-docs-badmodel".to_string(),
        task_provider_item_id: None,
        task_function_call_id: None,
    };
    let completion = driver
        .execute_batch_noninteractive_task(task, &tx, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert!(
        completion
            .children
            .iter()
            .all(|c| !c.report.contains("could not load")),
        "an unresolvable docs model must NOT surface a `load(\"docs\")` error: {:?}",
        completion
            .children
            .iter()
            .map(|c| &c.report)
            .collect::<Vec<_>>()
    );
    assert!(
        completion
            .children
            .iter()
            .any(|c| c.failed && c.report.contains("docs-entry")),
        "the unresolvable docs-stage model fails CLOSED with a content-safe routing error: {:?}",
        completion
            .children
            .iter()
            .map(|c| &c.report)
            .collect::<Vec<_>>()
    );
}

/// K1 (AC7/AC8): a child's agent DEFINITION is a second live input the config pin
/// does NOT cover — `builtin::load` re-reads the workspace/DB def at dispatch,
/// independent of the admission-surface resolution. A read-only custom child is
/// admitted to a SHARED READ guard; its def is then rewritten to expose a `write`
/// tool BEFORE the dispatch build (a concurrent def edit, driven here by a task
/// that rewrites the def file while the batch is suspended at its first await,
/// AFTER the admission loop read the read-only def). The built child is now
/// write-capable — it must NOT dispatch write-capable under the read guard it
/// holds: the post-build re-derivation catches that its real surface is more
/// privileged than its guard class and FAILS CLOSED, dispatching NO inference.
/// (Pre-fix, the child would build write-capable and dispatch under the read
/// guard — a concurrent-write violation — so this test is non-vacuous.)
#[test]
fn batch_read_only_child_fails_closed_if_def_gains_write_before_build() {
    let provider = cockpit_test_support::provider::ScriptedProvider::builder()
        .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
        .turn(cockpit_test_support::provider::Turn::Text("done".into()))
        .repeat_last()
        .start_blocking();
    let url = provider.base_url();
    let batch_thread = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (mut driver, _tmp) = test_driver_with_url_vnext(8, url.clone());
                    let config_dir = driver.cwd.join(".cockpit");
                    let providers_dir = config_dir.join("providers");
                    std::fs::create_dir_all(&providers_dir).unwrap();
                    // `web.provider = custom` suppresses the default webfetch/websearch
                    // (Dynamic) so a `[read]` custom child is genuinely read-only
                    // eligible → admitted to a SHARED read guard.
                    std::fs::write(
                        config_dir.join("config.json"),
                        r#"{"agent_chooses_subagent_model": true, "web": {"provider": "custom"}, "active_model": {"provider":"lmstudio","model":"local"}}"#,
                    )
                    .unwrap();
                    std::fs::write(
                        providers_dir.join("lmstudio.json"),
                        serde_json::json!({
                            "url": url,
                            "models": [{ "id": "local", "subagent_invokable": true }]
                        })
                        .to_string(),
                    )
                    .unwrap();
                    let agents_dir = config_dir.join("agents");
                    std::fs::create_dir_all(&agents_dir).unwrap();
                    let probe_path = agents_dir.join("probe.md");
                    // Admission-time def: read-only → concurrently admissible.
                    std::fs::write(
                        &probe_path,
                        vnext_coding_agent_document(
                            "probe",
                            "read-only probe",
                            "Investigate read-only.",
                        ),
                    )
                    .unwrap();
                    write_host_tool_surface(&agents_dir, "probe", &["read"]);
                    admit_authored_child_to_test_grants(&mut driver, "authored/probe");
                    driver.refresh_config_from_disk_for_tests();
                    let trust_cwd = driver.cwd.clone();
                    let _trust = crate::config::trust::enter_workspace_trust_policy(
                        crate::config::trust::WorkspaceTrustPolicy {
                            root: crate::config::trust::resolve_trust_root(&trust_cwd)
                                .unwrap_or_else(|_| crate::config::trust::TrustRoot {
                                    opened_path: trust_cwd.clone(),
                                    root: trust_cwd.clone(),
                                    kind: crate::config::trust::TrustRootKind::Directory,
                                }),
                            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                        },
                    );
                    seed_batch_task_delegation(&driver, "task-def-race", &["probe"]).await;
                    seed_task_payload(&driver, "task-def-race", "probe", "probe").await;
                    // Def-mutator: on its first poll — during the batch's first await,
                    // AFTER the synchronous admission loop already read the read-only
                    // def, BEFORE the child future's dispatch `load` — rewrite the host
                    // tool surface to expose a `write` tool (a concurrent def edit).
                    let mutate_tools = agents_dir.join("probe.tools.json");
                    tokio::spawn(async move {
                        std::fs::write(
                            &mutate_tools,
                            serde_json::to_string(&["read", "write"]).unwrap(),
                        )
                        .unwrap();
                    });
                    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
                    let task = BatchNoninteractiveTask {
                        entries: vec![batch_entry("probe", "probe", None)],
                        child_cwds: vec![root_child_cwd(&driver)],
                        why: "test".to_string(),
                        repair_notes: Vec::new(),
                        task_call_id: "task-def-race".to_string(),
                        task_provider_item_id: None,
                        task_function_call_id: None,
                    };
                    driver
                        .execute_batch_noninteractive_task(
                            task,
                            &tx,
                            tokio_util::sync::CancellationToken::new(),
                        )
                        .await
                        .unwrap()
                })
        })
        .unwrap();

    let completion = batch_thread.join().unwrap();
    assert_eq!(completion.children.len(), 1);
    let child = &completion.children[0];
    assert!(
        child.failed && child.report.contains("re-delegate"),
        "a read-only child whose def gained `write` before the build FAILS CLOSED rather than \
         dispatching write-capable under its read guard: {}",
        child.report
    );
    assert_eq!(
        provider.request_count(),
        0,
        "no inference is dispatched under the read guard on the fail-closed path"
    );
}

/// Round-10: single delegation repins the config to a held snapshot for the
/// attempt, so a concurrent refresh mid-attempt is INVISIBLE to the attempt — the
/// child builds, dispatches, and records its write-scope grant under the PINNED
/// (pre-refresh) generation, with NO split and NO fail-closed. Driven on a
/// big-stack thread (avoiding the pre-existing deep-batch overflow): a bumper
/// advances the LIVE shared generation while `execute_single` is suspended at its
/// first await (AFTER the synchronous repin), then a long-delayed provider parks
/// the child's request in flight so the main thread can confirm the child
/// dispatched AND its grant was recorded — proving the attempt ran the pinned
/// generation, not the refreshed one. (Under the old fail-closed behaviour the
/// move would abort with no request and no grant.)
#[test]
fn single_delegation_runs_under_pinned_generation_across_refresh() {
    let provider = cockpit_test_support::provider::ScriptedProvider::builder()
        .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
        .turn(cockpit_test_support::provider::Turn::Text("done".into()))
        .with_delay(std::time::Duration::from_secs(20))
        .repeat_last()
        .start_blocking();
    let url = provider.base_url();
    let cancel = tokio_util::sync::CancellationToken::new();
    let attempt_cancel = cancel.clone();
    let bumped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bumped_thread = bumped.clone();
    let (handoff_tx, handoff_rx) = std::sync::mpsc::channel::<(
        std::sync::Arc<crate::approval::Approver>,
        std::path::PathBuf,
    )>();
    let attempt_thread = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (mut driver, _tmp) = test_driver_with_url_vnext(8, url.clone());
                    let config_dir = driver.cwd.join(".cockpit");
                    let providers_dir = config_dir.join("providers");
                    std::fs::create_dir_all(&providers_dir).unwrap();
                    std::fs::write(
                        config_dir.join("config.json"),
                        r#"{"agent_chooses_subagent_model": true, "active_model": {"provider":"lmstudio","model":"local"}}"#,
                    )
                    .unwrap();
                    std::fs::write(
                        providers_dir.join("lmstudio.json"),
                        serde_json::json!({
                            "url": url,
                            "models": [
                                { "id": "local", "subagent_invokable": true },
                                { "id": "child-x", "subagent_invokable": true }
                            ]
                        })
                        .to_string(),
                    )
                    .unwrap();
                    driver.refresh_config_from_disk_for_tests();
                    set_root_scoped_parallel_write(&mut driver);
                    // Install a LIVE handle over a shared cell we control, so a bump
                    // is observable to any LIVE reader — but NOT to the pinned
                    // attempt (which is exactly the invariant under test).
                    let snapshot = (*driver.config.snapshot()).clone();
                    let shared = std::sync::Arc::new(std::sync::RwLock::new(snapshot));
                    driver.set_config_handle(
                        crate::daemon::session_worker::SessionConfigHandle::new(shared.clone()),
                    );
                    let approver = install_test_approver(&mut driver);
                    let scope = driver.cwd.join("scope");
                    std::fs::create_dir_all(&scope).unwrap();
                    seed_task_delegation(&driver, "task-pin", "default").await;
                    seed_task_payload(&driver, "task-pin", "default", "builder").await;
                    handoff_tx.send((approver.clone(), scope.clone())).unwrap();
                    // Bump the LIVE shared generation on the bumper's first poll —
                    // performed when `execute_single` first suspends, i.e. AFTER its
                    // synchronous repin pinned the attempt and BEFORE the child is
                    // built/dispatched.
                    tokio::spawn(async move {
                        let mut w = shared.write().unwrap();
                        w.generation += 1;
                        bumped_thread.store(true, std::sync::atomic::Ordering::SeqCst);
                    });
                    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
                    let mut task = single_task(
                        &driver,
                        "builder",
                        "task-pin",
                        Some(exact_model_selector("child-x")),
                        None,
                    );
                    task.write_scope = Some("scope".to_string());
                    let _ = driver
                        .execute_single_noninteractive_task(task, &tx, attempt_cancel)
                        .await;
                })
        })
        .unwrap();

    let (approver, scope) = handoff_rx.recv().unwrap();
    let probe_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut dispatched_and_granted = false;
    for _ in 0..200 {
        if provider.request_count() >= 1
            && probe_rt.block_on(approver.store().is_path_granted_for(
                &scope,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
            ))
        {
            dispatched_and_granted = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    cancel.cancel();
    attempt_thread.join().unwrap();
    assert!(
        bumped.load(std::sync::atomic::Ordering::SeqCst),
        "the concurrent refresh (live-generation bump) ran during the attempt"
    );
    assert!(
        dispatched_and_granted,
        "the child dispatched and its write-scope grant was recorded under the PINNED generation \
         despite a concurrent refresh — no split, no fail-closed, no orphaned grant"
    );
}

/// Round-10/11 (docs): the docs pipeline runs entirely under the attempt's PINNED
/// config — `docs_pipeline::run` and BOTH its stages read `spawn_args.config`,
/// which is the pinned handle. A concurrent refresh mid-attempt is therefore
/// invisible: Docs.1 (resolver) AND Docs.2 (answerer, which re-reads the SAME
/// `spawn_args.config`) dispatch under one generation, consistent with the handoff
/// expansion. Non-vacuous: the resolver is scripted to call `list-packages`, which
/// records a pre-registered `DocsResolution`, so Docs.2 actually launches — and we
/// assert BOTH stages dispatched (`request_count >= 2`) across a concurrent
/// refresh. A bumper advances the LIVE shared generation while `execute_single` is
/// suspended (AFTER its repin).
#[test]
fn docs_pipeline_runs_under_pinned_generation_across_refresh() {
    let provider = cockpit_test_support::provider::ScriptedProvider::builder()
        .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
        // Docs.1: the resolver calls `list-packages` (records the pre-registered
        // package as resolved), then concludes with text; Docs.2's answerer then
        // gets text too (repeat_last) and concludes. Both stages issue a request.
        .turn(cockpit_test_support::provider::Turn::ToolCall {
            id: "call-1".into(),
            name: "list-packages".into(),
            arguments: serde_json::json!({}),
        })
        .turn(cockpit_test_support::provider::Turn::Text(
            "resolved".into(),
        ))
        .repeat_last()
        .start_blocking();
    let url = provider.base_url();
    let bumped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bumped_thread = bumped.clone();
    let attempt_thread = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (mut driver, _tmp) = test_driver_with_url(8, url.clone());
                    let config_dir = driver.cwd.join(".cockpit");
                    let providers_dir = config_dir.join("providers");
                    std::fs::create_dir_all(&providers_dir).unwrap();
                    std::fs::write(
                        config_dir.join("config.json"),
                        r#"{"agent_chooses_subagent_model": true, "active_model": {"provider":"lmstudio","model":"local"}}"#,
                    )
                    .unwrap();
                    std::fs::write(
                        providers_dir.join("lmstudio.json"),
                        serde_json::json!({
                            "url": url,
                            "models": [
                                { "id": "local", "subagent_invokable": true },
                                { "id": "docs-child", "subagent_invokable": true }
                            ]
                        })
                        .to_string(),
                    )
                    .unwrap();
                    driver.refresh_config_from_disk_for_tests();
                    let snapshot = (*driver.config.snapshot()).clone();
                    let shared = std::sync::Arc::new(std::sync::RwLock::new(snapshot));
                    driver.set_config_handle(
                        crate::daemon::session_worker::SessionConfigHandle::new(shared.clone()),
                    );
                    // Pre-register (on disk) the package the resolver's
                    // `list-packages` call will match, so Docs.1 records a
                    // `DocsResolution` and Docs.2 launches.
                    let pkg_dir = driver.cwd.join("pkg-src");
                    std::fs::create_dir_all(&pkg_dir).unwrap();
                    driver
                        .session
                        .db
                        .upsert_package(&crate::db::packages::NewPackage {
                            identifier: "cargo:testpkg".into(),
                            display_name: "testpkg".into(),
                            source_type: crate::db::packages::SourceType::Local,
                            source_url: None,
                            source_branch: None,
                            path: pkg_dir.to_string_lossy().into_owned(),
                            shallow: false,
                            prepare_scope: "global".into(),
                        })
                        .await
                        .unwrap();
                    seed_task_delegation(&driver, "task-docs-pin", "default").await;
                    // The docs payload-delivery path requires the payload row to
                    // exist (content is unused for docs — the delivered brief is the
                    // task's own `brief`, set below).
                    seed_task_payload(&driver, "task-docs-pin", "default", "docs").await;
                    tokio::spawn(async move {
                        let mut w = shared.write().unwrap();
                        w.generation += 1;
                        bumped_thread.store(true, std::sync::atomic::Ordering::SeqCst);
                    });
                    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
                    let mut task = single_task(
                        &driver,
                        "docs",
                        "task-docs-pin",
                        Some(exact_model_selector("docs-child")),
                        None,
                    );
                    // A structured docs brief naming the pre-registered package (the
                    // docs pipeline parses the package + question out of the brief).
                    // The question carries a distinctive marker: it is WITHHELD from
                    // the resolver (Docs.1's brief is only `Package: <name>`) and
                    // appears ONLY in the answerer's (Docs.2's) brief, so finding it
                    // in a captured request body proves Docs.2 actually dispatched.
                    task.brief =
                        r#"{"package": "testpkg", "question": "ANSWERER-QUESTION-MARKER how do I use it?"}"#
                            .to_string();
                    let _ = driver
                        .execute_single_noninteractive_task(
                            task,
                            &tx,
                            tokio_util::sync::CancellationToken::new(),
                        )
                        .await;
                })
        })
        .unwrap();

    attempt_thread.join().unwrap();
    assert!(
        bumped.load(std::sync::atomic::Ordering::SeqCst),
        "the concurrent refresh ran during the docs attempt"
    );
    // Genuinely non-vacuous: Docs.1 alone makes 2 requests (its `list-packages`
    // tool call + the follow-up text), so a bare `>= 2` would pass even if Docs.2
    // were bypassed. Prove the ANSWERER dispatched by finding its unique question
    // marker in a captured request body (never present in the resolver's brief).
    let captured = provider.captured();
    let answerer_dispatched = captured
        .iter()
        .any(|req| req.body.to_string().contains("ANSWERER-QUESTION-MARKER"));
    assert!(
        answerer_dispatched,
        "Docs.2 (answerer) dispatched its own request (bearing the withheld question) under the \
         pinned generation across a concurrent refresh; captured {} requests",
        captured.len()
    );
}

#[tokio::test]
async fn unknown_agent_refusal_emits_no_spawn_or_amend_but_still_reports() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-load-failure", "default").await;
    seed_task_payload(&driver, "task-load-failure", "default", "missing-agent").await;
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
    assert!(
        completion.report.contains("unknown agent `missing-agent`"),
        "{}",
        completion.report
    );
    assert!(
        !completion.report.contains("failed to load"),
        "{}",
        completion.report
    );

    let events = drain_turn_events(&mut rx);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::SubagentSpawned { task_call_id, .. } if task_call_id == "task-load-failure"))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::SubagentRouting { task_call_id, .. } if task_call_id == "task-load-failure"))
    );
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
                task_provider_item_id: None,
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                failure: None,
                partial_progress: DelegationPartialProgress::default(),
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
                task_provider_item_id: None,
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
                already_terminal_labels: std::collections::BTreeSet::new(),
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
                task_provider_item_id: None,
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
                already_terminal_labels: std::collections::BTreeSet::new(),
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

#[tokio::test]
async fn queued_user_input_backgrounds_running_single_delegation() {
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

#[tokio::test]
async fn queued_user_input_backgrounds_running_batch_delegation() {
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

#[tokio::test]
async fn noninteractive_registry_is_live_only_for_running_and_backgrounded() {
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

#[tokio::test]
async fn noninteractive_registry_completion_status_uses_host_flag() {
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

#[tokio::test]
async fn host_failure_sentinel_matches_only_host_error_shape() {
    assert!(is_host_failure_sentinel("Error: boom"));
    assert!(is_host_failure_sentinel("  Error: leading ws"));
    assert!(!is_host_failure_sentinel("Error:nospace"));
    assert!(!is_host_failure_sentinel("## Accomplished\nError: quoted"));
}

#[tokio::test]
async fn task_control_orphan_list_status_cancel_and_refuse_live_actions() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-orphan", "default").await;

    let list = driver
        .dispatch_task_control(TaskControlAction::List, None, None, None)
        .await;
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

    let status = driver
        .dispatch_task_control(
            TaskControlAction::Status,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            None,
        )
        .await;
    let status_json: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status_json["state"], "status");
    assert_eq!(status_json["children"][0]["status"], "lost");
    assert_eq!(status_json["children"][0]["orphaned"], true);

    let query = driver
        .dispatch_task_control(
            TaskControlAction::Query,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            None,
        )
        .await;
    let query_json: serde_json::Value = serde_json::from_str(&query).unwrap();
    assert_eq!(query_json["state"], "refused");
    assert_eq!(query_json["actionable"], false);
    assert_eq!(
        query_json["reason"],
        "lost (daemon restarted; no live worker)"
    );
    assert_eq!(query_json["report_source"], "none");
    assert_eq!(query_json["children"][0]["status"], "lost");

    let steer = driver
        .dispatch_task_control(
            TaskControlAction::Steer,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            Some("please continue".to_string()),
        )
        .await;
    let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
    assert_eq!(steer_json["state"], "refused");
    assert_eq!(steer_json["actionable"], false);
    assert_eq!(
        steer_json["reason"],
        "lost (daemon restarted; no live worker)"
    );
    assert_eq!(steer_json["children"][0]["status"], "lost");

    let cancel = driver
        .dispatch_task_control(
            TaskControlAction::Cancel,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            None,
        )
        .await;
    let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
    assert_eq!(cancel_json["state"], "lost");
    assert_eq!(cancel_json["cancelled"].as_array().unwrap().len(), 0);
    assert_eq!(cancel_json["orphaned_lost"][0], "task-orphan:default");
    let rows = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .await
        .unwrap();
    assert_eq!(
        rows[0].status,
        crate::db::task_delegations::DelegationStatus::Lost
    );
}

#[tokio::test]
async fn task_control_live_registry_entry_keeps_happy_path() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-live", "default").await;
    driver.noninteractive_delegations.register_running(
        "task-live",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live context")]),
    );

    let list = driver
        .dispatch_task_control(TaskControlAction::List, None, None, None)
        .await;
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

    let query = driver
        .dispatch_task_control(
            TaskControlAction::Query,
            Some("task-live".to_string()),
            Some("default".to_string()),
            None,
        )
        .await;
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

    let steer = driver
        .dispatch_task_control(
            TaskControlAction::Steer,
            Some("task-live".to_string()),
            Some("default".to_string()),
            Some("keep going".to_string()),
        )
        .await;
    let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
    assert_eq!(steer_json["state"], "steer_queued");
    assert_eq!(steer_json["applies_at"], "next_child_turn_boundary");
    assert_eq!(steer_json["applies_if"], "child_still_running_actionable");
    assert_eq!(steer_json["children"][0]["pending_steers"], 1);

    let cancel = driver
        .dispatch_task_control(
            TaskControlAction::Cancel,
            Some("task-live".to_string()),
            Some("default".to_string()),
            None,
        )
        .await;
    let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
    assert_eq!(cancel_json["state"], "cancelled");
    assert_eq!(cancel_json["cancelled"][0], "task-live:default");
    let rows = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .await
        .unwrap();
    assert_eq!(
        rows[0].status,
        crate::db::task_delegations::DelegationStatus::Cancelled
    );
}

#[tokio::test]
async fn task_query_reports_db_and_none_sources() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-db", "default").await;
    driver
        .session
        .db
        .write(move |conn| {
            conn.execute(
                "UPDATE task_delegation_children SET report = 'db report' WHERE task_call_id = 'task-db' AND label = 'default'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap();
    driver.noninteractive_delegations.register_running(
        "task-db",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live fallback")]),
    );

    let db_query = driver
        .dispatch_task_control(
            TaskControlAction::Query,
            Some("task-db".to_string()),
            Some("default".to_string()),
            None,
        )
        .await;
    let db_json: serde_json::Value = serde_json::from_str(&db_query).unwrap();
    assert_eq!(db_json["state"], "query");
    assert_eq!(db_json["report_source"], "db");
    assert_eq!(db_json["report"], "db report");
    assert_eq!(db_json["report_available"], true);

    seed_task_delegation(&driver, "task-none", "default").await;
    driver.noninteractive_delegations.register_running(
        "task-none",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    let none_query = driver
        .dispatch_task_control(
            TaskControlAction::Query,
            Some("task-none".to_string()),
            Some("default".to_string()),
            None,
        )
        .await;
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

#[tokio::test]
async fn late_noninteractive_completion_delivers_once() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.background_on_user_input("task-1", "default"));

    let result = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
        "task-1".to_string(),
        None,
        None,
        "task",
        "done".to_string(),
    );
    assert!(registry.complete("task-1", "default", "done".to_string(), false, Some(result)));
    assert!(
        !registry.complete(
            "task-1",
            "default",
            "duplicate".to_string(),
            false,
            Some(
                crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                    "task-1".to_string(),
                    None,
                    None,
                    "task",
                    "duplicate".to_string(),
                )
            )
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

#[tokio::test]
async fn background_ack_is_small_deterministic_and_omits_original_prompt() {
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

#[tokio::test]
async fn async_delegation_result_lists_only_new_children_with_status() {
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
#[tokio::test]
async fn async_result_header_names_kind_and_job_id_for_every_kind() {
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
#[tokio::test]
async fn delivery_event_data_carries_job_id_round_trip() {
    let (driver, _t) = test_driver(1);
    let session = driver.session.clone();

    // Async-result delivery: `data.job_id` present.
    let delivery = user_message_event_data(UserMessageEventData {
        text: "[async result · loop · sched-abc]\nok",
        display_text: None,
        tag_expansions: &[],
        job_id: Some("sched-abc"),
        queue_item_ids: &[],
        client_submissions: &[],
        queue_target: None,
        preflight_cleaned: None,
    });
    session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &delivery,
        )
        .await
        .unwrap();
    // Ordinary user input: no `job_id` key.
    let ordinary = user_message_event_data(UserMessageEventData {
        text: "hello",
        display_text: None,
        tag_expansions: &[],
        job_id: None,
        queue_item_ids: &[],
        client_submissions: &[],
        queue_target: None,
        preflight_cleaned: None,
    });
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
        .await
        .unwrap();

    let events = session.db.list_session_events(session.id).await.unwrap();
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

// J4 behavioral (AC15): a docs-pipeline finalizer must journal its report
// through the frame the DocsPipelineReport's authoring model yields — NOT a
// source grep. These tests build a real `DocsPipelineReport`, derive the
// finalizer's `DelegationChildOutcome` + `ChildRoutingMetadata::from_model`
// EXACTLY as the single/batch finalizers do, then drive the resulting
// `SessionEventModelFrame` through the production chokepoint and assert the
// protected-redaction-history outcome. A regression that drops `report_model`
// (frame-less `record_event`) leaves the literal unjournaled and fails the
// positive assertion; a broken frame fails the fail-closed assertion.

fn docs_report_redact_cfg() -> crate::config::extended::RedactConfig {
    crate::config::extended::RedactConfig {
        enabled: true,
        scan_environment: true,
        scan_dotenv: false,
        scan_ssh_keys: false,
        min_secret_length: 4,
        placeholder: "[redacted]".to_string(),
        ..crate::config::extended::RedactConfig::default()
    }
}

/// A pre-policy session table carrying a single `Environment` literal `lit`.
fn docs_report_env_table(lit: &str) -> RedactionTable {
    let env = std::collections::HashMap::from([("DEPLOY_TOKEN".to_string(), lit.to_string())]);
    RedactionTable::build_with_env(&docs_report_redact_cfg(), std::path::Path::new("."), &env)
        .unwrap()
}

/// Providers config with a trusted `openai:gpt-5`, so a `Model` built for it
/// resolves a trusted journaling frame.
fn write_docs_report_trusted_provider(root: &std::path::Path) {
    let cockpit = root.join(".cockpit");
    let providers = cockpit.join("providers");
    std::fs::create_dir_all(&providers).unwrap();
    std::fs::write(cockpit.join("config.json"), "{}").unwrap();
    std::fs::write(
        providers.join("openai.json"),
        serde_json::json!({
            "url": "https://example.test/v1",
            "models": [{"id": "gpt-5", "trust": "trusted"}],
        })
        .to_string(),
    )
    .unwrap();
}

/// Build the exact `DelegationChildOutcome` a docs finalizer produces from the
/// pipeline report — `DelegationChildOutcome::ok(report.report)` +
/// `with_child_routing(ChildRoutingMetadata::from_model(report.report_model.as_ref()))`
/// — from a real trusted `DocsPipelineReport`. Returns the outcome plus the
/// event data the finalizer journals.
fn docs_finalizer_outcome_and_data(
    providers: &crate::config::providers::ProvidersConfig,
    report_text: &str,
) -> (DelegationChildOutcome, serde_json::Value) {
    let report_model = Arc::new(
        crate::engine::model::Model::for_provider(
            providers,
            "openai",
            "gpt-5",
            Arc::new(RedactionTable::empty()),
        )
        .unwrap(),
    );
    let report = crate::engine::docs_pipeline::DocsPipelineReport {
        report: report_text.to_string(),
        report_model,
    };
    // Mirror the single/batch docs `Ok` arm verbatim.
    let outcome = DelegationChildOutcome::ok(report.report).with_child_routing(
        ChildRoutingMetadata::from_model(report.report_model.as_ref()),
    );
    let routing = outcome
        .child_routing
        .as_ref()
        .expect("docs finalizer attaches child routing");
    let report_data = with_child_routing_metadata(
        subagent_report_event_data(
            "docs",
            Some("task-docs"),
            None,
            None,
            "default",
            &outcome.report,
            None,
        ),
        routing,
    );
    (outcome, report_data)
}

#[tokio::test]
async fn docs_finalizer_report_model_frame_journals_table_literal() {
    const LIT: &str = "docs-report-frame-secret-abc123456";

    let tmp = tempfile::tempdir().unwrap();
    write_docs_report_trusted_provider(tmp.path());
    let db = crate::db::Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    let config =
        crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
    let (_extended, providers) = config.configs();
    let table = docs_report_env_table(LIT);

    let (outcome, report_data) =
        docs_finalizer_outcome_and_data(&providers, &format!("docs answer cites {LIT}"));
    let routing = outcome.child_routing.as_ref().unwrap();

    // Drive the SAME frame the finalizer builds from the report's authoring
    // model through the production chokepoint.
    let seq = session
        .record_event_with_model_frame(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("docs"),
            Some("task-docs"),
            crate::session::SessionEventModelFrame {
                provider_id: &routing.provider,
                model_id: &routing.model,
                config: &config,
                session_table: &table,
            },
            &report_data,
        )
        .await
        .unwrap();

    // Behavioral proof: the docs report's table literal journaled to one
    // history row, referenced by this event's committed `seq` as an Event
    // artifact.
    let sid = session.id.to_string();
    let rows = db.protected_redaction_history_list(&sid).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the docs-report frame must journal the table literal: {rows:#?}"
    );
    let refs = db
        .protected_redaction_artifact_refs_for_artifact(
            crate::redact::protected_redaction_history::RedactionArtifactKind::Event,
            &seq.to_string(),
        )
        .await
        .unwrap();
    assert_eq!(refs.len(), 1, "one Event ref for the docs report seq");
    assert_eq!(refs[0].history_id, rows[0].history_id);
}

#[tokio::test]
async fn docs_finalizer_report_model_frame_fails_closed_on_journal_failure() {
    const LIT: &str = "docs-report-frame-secret-xyz987654";

    let tmp = tempfile::tempdir().unwrap();
    write_docs_report_trusted_provider(tmp.path());
    let db = crate::db::Db::open_in_memory().unwrap();
    // A faulted store-backed resolver: journaling is attempted (the frame is
    // trusted) and its first `prepare_append` fails, driving the real
    // decision-12 event fallback that scrubs the persisted body.
    let (session, actor) = docs_faulted_journaling_session(&db).await;
    let config =
        crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
    let (_extended, providers) = config.configs();
    let table = docs_report_env_table(LIT);

    let (outcome, report_data) =
        docs_finalizer_outcome_and_data(&providers, &format!("docs answer cites {LIT}"));
    let routing = outcome.child_routing.as_ref().unwrap();

    let seq = session
        .record_event_with_model_frame(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("docs"),
            Some("task-docs"),
            crate::session::SessionEventModelFrame {
                provider_id: &routing.provider,
                model_id: &routing.model,
                config: &config,
                session_table: &table,
            },
            &report_data,
        )
        .await
        .expect("journal failure must fail closed, not abort the turn");

    // No history row committed, and the persisted event body carries the
    // generic placeholder in place of the raw literal.
    assert!(
        db.protected_redaction_history_list(&session.id.to_string())
            .await
            .unwrap()
            .is_empty(),
        "journal failure leaves no history row"
    );
    let events = db.list_session_events(session.id).await.unwrap();
    let event = events
        .iter()
        .find(|e| e.seq == seq)
        .expect("scrubbed docs report event persisted");
    let stored = serde_json::to_string(&event.data).unwrap();
    assert!(!stored.contains(LIT), "matched literal must be scrubbed");
    assert!(stored.contains("[redacted]"), "generic placeholder present");

    docs_shutdown_fake_secure_key_actor(actor).await;
}

/// Boot the production secure-key actor over a caller-held FakeNativeStore off
/// the runtime (the `start_with_store` handshake blocks). Mirrors the recording
/// tests' AC15 pattern — `MapKeyResolver` is for pure-crypto unit tests only.
async fn docs_boot_fake_secure_key_actor(
    db: &crate::db::Db,
    store: &crate::secure_key::fake::FakeNativeStore,
) -> crate::secure_key::SecureKeyActor {
    let db = db.clone();
    let store = store.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("docs-test-secure-key-boot".into())
        .spawn(move || {
            let _ = tx.send(crate::secure_key::SecureKeyActor::start_with_store(
                db,
                Box::new(store),
                std::sync::Arc::new(crate::secure_key::FailClosedReconciler),
            ));
        })
        .expect("spawn secure key boot thread");
    rx.await
        .expect("secure key boot channel")
        .expect("secure key actor")
}

async fn docs_shutdown_fake_secure_key_actor(actor: crate::secure_key::SecureKeyActor) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("docs-test-secure-key-shutdown".into())
        .spawn(move || {
            drop(actor);
            let _ = tx.send(());
        })
        .expect("spawn secure key shutdown thread");
    rx.await.expect("secure key shutdown channel");
}

/// A session whose journaling resolver is backed by a `FaultKind::Unavailable`
/// FakeNativeStore, so the first `prepare_append` a trusted journal attempts
/// fails and drives the real decision-12 fallback.
async fn docs_faulted_journaling_session(
    db: &crate::db::Db,
) -> (Session, crate::secure_key::SecureKeyActor) {
    use crate::secure_key::fake::{FakeNativeStore, FaultKind, FaultPoint, InjectedFault};
    let store = FakeNativeStore::new();
    let actor = docs_boot_fake_secure_key_actor(db, &store).await;
    store.inject(
        FaultPoint::BeforeGet,
        InjectedFault::Error(FaultKind::Unavailable),
    );
    store.inject(
        FaultPoint::BeforeSet,
        InjectedFault::Error(FaultKind::Unavailable),
    );
    let resolver: std::sync::Arc<
        dyn crate::redact::protected_redaction_history::RedactionKeyResolver,
    > = std::sync::Arc::new(crate::redact::secure_key_resolver::SecureKeyResolver::new(
        actor.handle(),
    ));
    let session = Session::create_for_test(
        db.clone(),
        std::path::PathBuf::from("/proj"),
        "Build",
        resolver,
    )
    .unwrap();
    (session, actor)
}

// ---------------------------------------------------------------------------
// delegated-model-harness-posture (AC1–AC8)
//
// Every delegated child renders and enforces the harness posture resolved for
// its OWN selected model, while `ModelTrust` stays an orthogonal dimension and
// parent-request batch admission stays parent-scoped.
// ---------------------------------------------------------------------------

/// Run `f` with `cwd` marked workspace-trusted, so an on-disk agent override in
/// `.cockpit/agents` is loaded (matching a trusted session root).
fn dmh_trusted<T>(cwd: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(cwd).unwrap_or_else(|_| {
            crate::config::trust::TrustRoot {
                opened_path: cwd.to_path_buf(),
                root: cwd.to_path_buf(),
                kind: crate::config::trust::TrustRootKind::Directory,
            }
        }),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::with_workspace_trust_policy(policy, f)
}

/// One `lmstudio` model entry, optionally pinning a per-model `trust`
/// (inference custody) override.
fn dmh_model(id: &str, trust: Option<&str>) -> serde_json::Value {
    let mut m = serde_json::json!({ "id": id, "subagent_invokable": true });
    if let Some(trust) = trust {
        m["trust"] = serde_json::json!(trust);
    }
    m
}

/// Install a delegated-model config: a base config (with the given overrides
/// merged in) plus the `lmstudio` provider carrying `models`, then refresh the
/// driver's config handle from disk.
fn dmh_install_config(
    driver: &mut Driver,
    config_overrides: serde_json::Value,
    models: Vec<serde_json::Value>,
) {
    let config_dir = driver.cwd.join(".cockpit");
    let providers_dir = config_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    let mut cfg = serde_json::json!({
        "agent_chooses_subagent_model": true,
        "active_model": { "provider": "lmstudio", "model": "local" }
    });
    if let serde_json::Value::Object(map) = config_overrides {
        let obj = cfg.as_object_mut().unwrap();
        for (k, v) in map {
            obj.insert(k, v);
        }
    }
    std::fs::write(config_dir.join("config.json"), cfg.to_string()).unwrap();
    std::fs::write(
        providers_dir.join("lmstudio.json"),
        serde_json::json!({ "url": test_provider_base_url(), "models": models }).to_string(),
    )
    .unwrap();
    driver.refresh_config_from_disk_for_tests();
}

/// Build a delegated child under `cwd`-trust and return the loaded agent.
fn dmh_build_child(
    driver: &Driver,
    child_agent: &str,
    interactive: bool,
    model: Option<crate::engine::model_roles::DelegationModelSelector>,
    recursion: crate::engine::builtin::DelegationRecursionContext,
) -> crate::engine::agent::Agent {
    let cwd = driver.cwd.clone();
    let args = driver.spawn_args_delegated_in_cwd(&cwd, interactive, Vec::new(), model, recursion);
    dmh_trusted(&cwd, || crate::engine::builtin::load(child_agent, &args)).unwrap()
}

/// A host-selected target model is runtime policy, not authored markdown.
/// Keep the custody test's selection axis explicit by constructing the
/// otherwise-v2 built-in definition at the trusted host boundary.
fn dmh_build_host_selected_child(
    driver: &Driver,
    child_agent: &str,
    model_selector: &str,
) -> crate::engine::agent::Agent {
    let cwd = driver.cwd.clone();
    let args = driver.spawn_args_delegated_in_cwd(
        &cwd,
        false,
        Vec::new(),
        None,
        crate::engine::builtin::DelegationRecursionContext::default(),
    );
    let mut definition =
        crate::agents::embedded_default(child_agent).expect("known host-owned child definition");
    definition.model = Some(model_selector.to_string());
    dmh_trusted(&cwd, || {
        crate::engine::builtin::agent_from_def(&definition, &args)
    })
    .unwrap()
}

/// A redaction sentinel: content that a session-scoped protected literal scrubs
/// on the outbound wire.
const DMH_WIRE_SECRET: &str = "sk-live-delegation-secret-XYZ";

/// Give the session model a redaction table carrying [`DMH_WIRE_SECRET`], so a
/// delegated child model INHERITS it: an untrusted child keeps the session
/// table (scrubs the sentinel on the wire), a trusted child resolves to the
/// empty passthrough (sentinel rides raw). Call after `dmh_install_config` so
/// the providers config is already on the config handle.
fn dmh_inject_session_secret(driver: &mut Driver) {
    let providers = driver.config.providers();
    let table = crate::redact::RedactionTable::empty()
        .with_forced_literal(DMH_WIRE_SECRET.to_string(), "REDACTED".to_string())
        .expect("forced literal");
    let model = std::sync::Arc::new(
        crate::engine::model::Model::from_config(&providers, std::sync::Arc::new(table)).unwrap(),
    );
    std::sync::Arc::make_mut(&mut driver.stack[0].agent).model = model;
}

/// Per-candidate re-posture fires on a MODEL change because the composed
/// `system` is model-specific (it prepends the candidate model's own system
/// prompt). A different-model backup is re-rendered (carrying the candidate
/// model); the primary model is a no-op.
#[tokio::test]
async fn delegated_failover_reposture_fires_on_model_change() {
    let (mut driver, _tmp) = test_driver(8);
    dmh_install_config(
        &mut driver,
        serde_json::json!({}),
        vec![
            dmh_model("local", None),
            dmh_model("model-a", None),
            dmh_model("model-b", None),
        ],
    );
    // An assistant-owned session: the identity/SOUL/USER prefix is prepended to
    // every child's composed system at build time.
    driver.set_assistant_identity_prefix(Some("SOUL-IDENTITY-MARKER".to_string()));
    let agent_a = dmh_build_child(
        &driver,
        "explore",
        false,
        Some(exact_model_selector("model-a")),
        crate::engine::builtin::DelegationRecursionContext::default(),
    );
    let agent_b = dmh_build_child(
        &driver,
        "explore",
        false,
        Some(exact_model_selector("model-b")),
        crate::engine::builtin::DelegationRecursionContext::default(),
    );
    assert_eq!(agent_a.model.model_id_ref(), "model-a");
    assert_eq!(agent_b.model.model_id_ref(), "model-b");
    // The build applied the identity prefix to the composed system.
    assert!(agent_a.system.contains("SOUL-IDENTITY-MARKER"));
    assert_eq!(
        agent_a.assistant_identity_prefix.as_deref(),
        Some("SOUL-IDENTITY-MARKER")
    );
    // DIFFERENT model → re-render (Some), carrying model-b. Re-render reuses
    // the agent's own role (no def re-resolution / no workspace-trust needed).
    let reposed = crate::engine::builtin::reposture_agent_for_candidate(
        &agent_a,
        &agent_b.model,
        &driver.session,
        &driver.cwd,
        &driver.session.db,
    )
    .await
    .unwrap()
    .expect("a different-model candidate is re-rendered");
    assert_eq!(
        reposed.model.model_id_ref(),
        "model-b",
        "the re-rendered agent carries the CANDIDATE model, not the primary's"
    );
    // The repostured system KEEPS the assistant identity prefix, and is
    // byte-identical to a fresh build for the candidate model (identity prefix +
    // role body) — fails if the reposture drops the prefix.
    assert!(
        reposed.system.contains("SOUL-IDENTITY-MARKER"),
        "the repostured system keeps the assistant identity prefix"
    );
    assert_eq!(
        reposed.system, agent_b.system,
        "the repostured system == a fresh build for the candidate model"
    );
    assert_eq!(
        reposed.assistant_identity_prefix.as_deref(),
        Some("SOUL-IDENTITY-MARKER")
    );

    // Same model → no-op (None).
    let noop = crate::engine::builtin::reposture_agent_for_candidate(
        &agent_a,
        &agent_a.model,
        &driver.session,
        &driver.cwd,
        &driver.session.db,
    )
    .await
    .unwrap();
    assert!(noop.is_none(), "the primary model is a no-op");
}

/// Trust alone selects raw-vs-redacted egress for a delegated child.
#[test]
fn delegated_trust_cartesian_matrix() {
    let trusts = [("trusted", true), ("untrusted", false)];

    for (trust_str, trusted) in trusts {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![
                dmh_model("local", None),
                dmh_model("probe", Some(trust_str)),
            ],
        );
        // Reach the trusted/untrusted probe through a HOST-authored
        // frontmatter model, so custody is the target's own class (a
        // model-directed selector would force redacted-untrusted custody).
        let agents_dir = driver.cwd.join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("explore.md"),
            vnext_coding_agent_document("explore", "probe", "Investigate read-only."),
        )
        .unwrap();
        // The session model carries a redaction sentinel so the child model
        // inherits it by trust class.
        dmh_inject_session_secret(&mut driver);

        let child = dmh_build_host_selected_child(&driver, "explore", "lmstudio:probe");
        assert_eq!(child.model.model_id_ref(), "probe", "cell {trust_str}");
        // Trust axis: the ACTUAL raw-vs-redacted WIRE egress follows trust
        // only. Scrub a sentinel-bearing payload through the child model's
        // effective outbound redaction table — the table that scrubs its
        // provider request body — and confirm the sentinel is removed iff
        // the child is untrusted.
        let wire = child
            .model
            .redact_table()
            .scrub(&format!("deploy with {DMH_WIRE_SECRET} now"));
        if trusted {
            assert!(
                wire.contains(DMH_WIRE_SECRET),
                "trusted child egress rides raw (trust={trust_str}): {wire}"
            );
        } else {
            assert!(
                !wire.contains(DMH_WIRE_SECRET),
                "untrusted child egress scrubs the sentinel (trust={trust_str}): {wire}"
            );
        }
        assert_eq!(
            child.model.is_trusted(),
            trusted,
            "egress class follows trust only (trust={trust_str})"
        );
    }
}

/// Drive ONE trust cell through the REAL delegated production turn against a
/// request-capturing provider, with a redaction sentinel in the brief, and
/// return whether the sentinel rode RAW in the actual captured request body.
fn dmh_captured_request_has_sentinel(trust: &str) -> bool {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn({
            let trust = trust.to_string();
            move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let provider = cockpit_test_support::provider::ScriptedProvider::builder()
                            .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
                            .turn(cockpit_test_support::provider::Turn::Text("done".into()))
                            .repeat_last()
                            .start_blocking();
                        let (mut driver, _tmp) = test_driver_with_url_vnext(8, provider.base_url());
                        let cwd = driver.cwd.clone();
                        let _trust = crate::config::trust::enter_workspace_trust_policy(
                            crate::config::trust::WorkspaceTrustPolicy {
                                root: crate::config::trust::resolve_trust_root(&cwd)
                                    .unwrap_or_else(|_| crate::config::trust::TrustRoot {
                                        opened_path: cwd.clone(),
                                        root: cwd.clone(),
                                        kind: crate::config::trust::TrustRootKind::Directory,
                                    }),
                                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                            },
                        );
                        let config_dir = driver.cwd.join(".cockpit");
                        let providers_dir = config_dir.join("providers");
                        std::fs::create_dir_all(&providers_dir).unwrap();
                        std::fs::write(
                            config_dir.join("config.json"),
                            r#"{"agent_chooses_subagent_model": true, "active_model": {"provider":"lmstudio","model":"local"}}"#,
                        )
                        .unwrap();
                        std::fs::write(
                            providers_dir.join("lmstudio.json"),
                            serde_json::json!({
                                "url": provider.base_url(),
                                "models": [
                                    { "id": "local", "subagent_invokable": true },
                                    { "id": "probe", "trust": trust, "subagent_invokable": true }
                                ]
                            })
                            .to_string(),
                        )
                        .unwrap();
                        // Host-authored frontmatter model → the child model keeps
                        // its OWN custody class (trusted or untrusted).
                        let agents_dir = config_dir.join("agents");
                        std::fs::create_dir_all(&agents_dir).unwrap();
                        std::fs::write(
                            agents_dir.join("explore.md"),
                            "---\ndescription: probe\nschemaVersion: 2\nagentId: cockpit/explore\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Execute the assigned coding task\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nInvestigate read-only.\n",
                        )
                        .unwrap();
                        driver.refresh_config_from_disk_for_tests();
                        // The session model carries the sentinel redaction table so
                        // the child model inherits it by trust class.
                        dmh_inject_session_secret(&mut driver);
                        // The target model is host-selected runtime policy.  Do
                        // not put a selector back into v2 markdown: the
                        // driver's model override is propagated into the child
                        // SpawnArgs and preserves the provider's trusted-vs-
                        // untrusted custody classification. Carry the session
                        // redaction table so an untrusted probe still scrubs.
                        let session_table = driver.stack[0].agent.model.session_redact_table();
                        let mut host_selected = driver.config.providers();
                        host_selected.active_model = Some(
                            crate::config::providers::ActiveModelRef {
                                provider: "lmstudio".to_string(),
                                model: "probe".to_string(),
                                reasoning_effort: None,
                                thinking_mode: None,
                                prompt_cache_retention: None,
                            },
                        );
                        driver.set_model_override(Some(std::sync::Arc::new(
                            crate::engine::model::Model::from_config(
                                &host_selected,
                                session_table,
                            )
                            .unwrap(),
                        )));

                        seed_task_delegation(&driver, "task-wire-egress", "default").await;
                        seed_task_payload(&driver, "task-wire-egress", "default", "explore").await;
                        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
                        let mut task = single_task(&driver, "explore", "task-wire-egress", None, None);
                        // The delegation brief carries the sentinel.
                        task.brief = format!("investigate {DMH_WIRE_SECRET} in the codebase");
                        let completion = driver
                            .execute_single_noninteractive_task(
                                task,
                                &tx,
                                tokio_util::sync::CancellationToken::new(),
                            )
                            .await
                            .unwrap();

                        let captured = provider.captured();
                        assert!(!captured.is_empty(), "the child dispatched a request");
                        let _ = completion;
                        captured
                            .iter()
                            .any(|r| r.body.to_string().contains(DMH_WIRE_SECRET))
                    })
            }
        })
        .unwrap()
        .join()
        .unwrap()
}

/// AC4 (wire egress, end-to-end): drive a trusted and an untrusted child through
/// the REAL delegated turn against a request-capturing provider — the CAPTURED
/// request body carries the sentinel RAW only for the TRUSTED target and SCRUBBED
/// for the untrusted one. This fails if production stopped applying the redaction
/// table at network egress. Two trust cells are driven end-to-end here because
/// full dispatch per cell is slow.
#[test]
fn delegated_trust_wire_egress_is_raw_only_for_trusted() {
    assert!(
        dmh_captured_request_has_sentinel("trusted"),
        "a trusted child's captured request carries the sentinel RAW"
    );
    assert!(
        !dmh_captured_request_has_sentinel("untrusted"),
        "an untrusted child's captured request SCRUBS the sentinel"
    );
}

/// Parent-request batch admission is parent-scoped: the parent agent's
/// `scopedParallelWrite` grant admits or refuses the write-capable parallel
/// batch. The child's own def posture is independent of that parent grant.
#[tokio::test]
async fn delegated_parent_authorization_remains_parent_scoped() {
    // (a) A parent with `scopedParallelWrite` admits the write-capable parallel
    //     batch (parent-scoped policy); the admitted child's surface still
    //     follows its OWN def, not the parent's grants.
    {
        let (mut driver, tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![dmh_model("local", None), dmh_model("child-a", None)],
        );
        set_root_scoped_parallel_write(&mut driver);
        std::fs::create_dir_all(tmp.path().join("a")).unwrap();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let mut entry = batch_entry_with_scope("a", "builder", "a");
        entry.model = Some(exact_model_selector("child-a"));
        let task = BatchNoninteractiveTask {
            entries: vec![entry],
            child_cwds: vec![root_child_cwd(&driver)],
            why: "test".to_string(),
            repair_notes: Vec::new(),
            task_call_id: "task-parent-scope-admit".to_string(),
            task_provider_item_id: None,
            task_function_call_id: None,
        };
        let completion = driver
            .execute_batch_noninteractive_task(
                task,
                &tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(
            !completion.children[0]
                .report
                .contains("scopedParallelWrite"),
            "parent with scopedParallelWrite admits the write-capable batch: {}",
            completion.children[0].report
        );
        let _ = drain_turn_events(&mut rx);

        let child = dmh_build_child(
            &driver,
            "builder",
            false,
            Some(exact_model_selector("child-a")),
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        assert_eq!(
            child.tool_steering,
            crate::agents::ToolSteering::from_def(
                &crate::agents::embedded_default("builder").unwrap(),
            )
        );
    }

    // (b) The same admission stays parent-scoped: a parent without
    //     `scopedParallelWrite` refuses the write-capable batch even when the
    //     child target is independently write-capable.
    {
        let (mut driver, tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![dmh_model("local", None), dmh_model("child-b", None)],
        );
        std::fs::create_dir_all(tmp.path().join("a")).unwrap();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        let mut entry = batch_entry_with_scope("a", "builder", "a");
        entry.model = Some(exact_model_selector("child-b"));
        let task = BatchNoninteractiveTask {
            entries: vec![entry],
            child_cwds: vec![root_child_cwd(&driver)],
            why: "test".to_string(),
            repair_notes: Vec::new(),
            task_call_id: "task-parent-scope-refuse".to_string(),
            task_provider_item_id: None,
            task_function_call_id: None,
        };
        let completion = driver
            .execute_batch_noninteractive_task(
                task,
                &tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(completion.children[0].failed);
        assert!(
            completion.children[0]
                .report
                .contains("scopedParallelWrite"),
            "admission is parent-scoped: a parent without scopedParallelWrite refuses: {}",
            completion.children[0].report
        );
    }
}

/// Identity always comes from ONE config generation, and a resolution/build
/// failure yields no surface (and thus no dispatch), never a fall back to the
/// parent for a different selected model.
#[tokio::test]
async fn delegated_build_failure_dispatches_nothing() {
    let (mut driver, _tmp) = test_driver(8);
    dmh_install_config(
        &mut driver,
        serde_json::json!({}),
        vec![dmh_model("local", None), dmh_model("child-a", None)],
    );
    let cwd = driver.cwd.clone();

    // A good child: its surface identity is resolved from the generation it
    // was built from — no cross-model or cross-generation mix.
    let good_args = driver.spawn_args_delegated_in_cwd(
        &cwd,
        false,
        Vec::new(),
        Some(exact_model_selector("child-a")),
        crate::engine::builtin::DelegationRecursionContext::default(),
    );
    let surface = dmh_trusted(&cwd, || {
        crate::engine::builtin::resolve_child_execution_surface("explore", &good_args)
    })
    .expect("good child resolves a surface");
    assert_eq!(surface.config_generation, good_args.config.generation());
    assert_eq!(surface.model, "child-a");
    assert_eq!(
        surface.tool_steering,
        crate::agents::ToolSteering::from_def(&crate::agents::embedded_default("explore").unwrap(),)
    );

    // Build/resolution failure: an unresolvable selected model yields NO surface
    // (nothing can be admitted or dispatched) and the content-safe routing
    // error — never a fall back to the parent posture.
    let bad_args = driver.spawn_args_delegated_in_cwd(
        &cwd,
        false,
        Vec::new(),
        Some(exact_model_selector("does-not-exist")),
        crate::engine::builtin::DelegationRecursionContext::default(),
    );
    let err = dmh_trusted(&cwd, || {
        crate::engine::builtin::resolve_child_execution_surface("explore", &bad_args)
    })
    .expect_err("unresolvable model yields no surface");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("subagent model selector"),
        "content-safe routing error, not a parent-posture fallback: {msg}"
    );
    // The failing build produced no child agent, so there is nothing to dispatch.
    assert!(dmh_trusted(&cwd, || crate::engine::builtin::load("explore", &bad_args)).is_err());

    // Drive the REAL single-delegation dispatch path with an unresolvable child
    // model (+ a write scope, an approver, and a request-counting provider): the
    // resolution failure fails closed at the VERY START — BEFORE the first child
    // lifecycle/spawn side effect — so there is NO `SubagentSpawned` event, NO
    // write-scope grant, and ZERO inference requests.
    let provider = cockpit_test_support::provider::ScriptedProvider::builder()
        .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
        .turn(cockpit_test_support::provider::Turn::Text(
            "SHOULD-NEVER-BE-DISPATCHED".into(),
        ))
        .repeat_last()
        .start_blocking();
    let (mut driver, tmp2) = test_driver_with_url(8, provider.base_url());
    let config_dir = driver.cwd.join(".cockpit");
    let providers_dir = config_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        r#"{"agent_chooses_subagent_model": true, "active_model": {"provider":"lmstudio","model":"local"}}"#,
    )
    .unwrap();
    std::fs::write(
        providers_dir.join("lmstudio.json"),
        serde_json::json!({
            "url": provider.base_url(),
            "models": [{ "id": "local", "subagent_invokable": true }]
        })
        .to_string(),
    )
    .unwrap();
    driver.refresh_config_from_disk_for_tests();
    let approver = install_test_approver(&mut driver);
    let scope = tmp2.path().join("scope");
    std::fs::create_dir_all(&scope).unwrap();

    // Drive the REAL backgroundable entry point (the one that PERSISTS the task
    // and REGISTERS the running child before spawning the inner executor). NOTE:
    // the task delegation is deliberately NOT seeded — a fail-closed preflight
    // must persist it itself only AFTER validation, i.e. never here.
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let mut task = single_task(
        &driver,
        "builder",
        "task-build-failure",
        Some(exact_model_selector("does-not-exist")),
        None,
    );
    task.write_scope = Some(scope.display().to_string());
    let message = driver
        .run_single_noninteractive_task_backgroundable(
            task,
            &queue,
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    // The wrapper returned the content-safe routing error as the tool result.
    let text = tool_result_text(&message);
    assert!(
        text.contains("subagent model selector"),
        "content-safe routing error from the real backgroundable path: {text}"
    );
    assert!(!text.contains("SHOULD-NEVER-BE-DISPATCHED"));
    // No running child was registered (register_running was never reached).
    assert!(
        !driver
            .noninteractive_delegations
            .is_live("task-build-failure", "default"),
        "a fail-closed preflight registers/persists no running child"
    );
    // Zero inference.
    assert_eq!(
        provider.request_count(),
        0,
        "resolution/build failure must perform NO inference dispatch"
    );
    // No spawn event.
    let events = drain_turn_events(&mut rx);
    assert!(
        !events.iter().any(|e| matches!(
            e,
            TurnEvent::SubagentSpawned { task_call_id, .. } if task_call_id == "task-build-failure"
        )),
        "no SubagentSpawned event on a fail-closed preflight"
    );
    // No write-scope pregrant.
    assert!(
        !approver
            .store()
            .is_path_granted_for(
                &scope,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite
            )
            .await,
        "no write-scope grant on a fail-closed preflight"
    );

    // FD: the BATCH background entry point also fails closed BEFORE persisting or
    // registering any child. A batch with an unresolvable entry model leaves no
    // task registration and dispatches no inference.
    {
        let (mut driver, _tmp3) = test_driver_with_url(8, provider.base_url());
        let config_dir = driver.cwd.join(".cockpit");
        let providers_dir = config_dir.join("providers");
        std::fs::create_dir_all(&providers_dir).unwrap();
        std::fs::write(
            config_dir.join("config.json"),
            r#"{"agent_chooses_subagent_model": true, "active_model": {"provider":"lmstudio","model":"local"}}"#,
        )
        .unwrap();
        std::fs::write(
            providers_dir.join("lmstudio.json"),
            serde_json::json!({
                "url": provider.base_url(),
                "models": [{ "id": "local", "subagent_invokable": true }]
            })
            .to_string(),
        )
        .unwrap();
        driver.refresh_config_from_disk_for_tests();
        let requests_before = provider.request_count();

        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let mut good = batch_entry("good", "explore", None);
        good.prompt = "ok".to_string();
        let mut bad = batch_entry(
            "bad",
            "explore",
            Some(exact_model_selector("does-not-exist")),
        );
        bad.prompt = "ok".to_string();
        let task = BatchNoninteractiveTask {
            entries: vec![good, bad],
            child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
            why: "test".to_string(),
            repair_notes: Vec::new(),
            task_call_id: "task-batch-build-failure".to_string(),
            task_provider_item_id: None,
            task_function_call_id: None,
        };
        let message = driver
            .run_batch_noninteractive_task_backgroundable(
                task,
                &queue,
                &tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(
            tool_result_text(&message).contains("subagent model selector"),
            "content-safe routing error from the batch backgroundable path: {}",
            tool_result_text(&message)
        );
        // No entry was registered running (register_running never reached).
        assert!(
            !driver
                .noninteractive_delegations
                .is_live("task-batch-build-failure", "good")
                && !driver
                    .noninteractive_delegations
                    .is_live("task-batch-build-failure", "bad"),
            "a fail-closed batch preflight registers no running child"
        );
        // No spawn event, no inference.
        let events = drain_turn_events(&mut rx);
        assert!(!events.iter().any(|e| matches!(
            e,
            TurnEvent::SubagentSpawned { task_call_id, .. } if task_call_id == "task-batch-build-failure"
        )));
        assert_eq!(
            provider.request_count(),
            requests_before,
            "a bad-model batch entry dispatches NO inference"
        );
    }
}

/// AC7: interactive and noninteractive selection expose one immutable surface
/// equal to the subsequently built attempt, with the child's OWN posture (no
/// root leak). `parallel_read_only_eligible` is false for a read-only-sounding
/// child whose real surface carries a dynamic/mutating tool, and for a child
/// exposing nested task/control/scheduling capability.
#[test]
fn resolved_child_execution_surface_matches_actual_attempt() {
    // The surface equals the subsequently built attempt for both interactive
    // and noninteractive delegation, and no root identity leaks in.
    for interactive in [true, false] {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![dmh_model("local", None), dmh_model("child-a", None)],
        );
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd(
            &cwd,
            interactive,
            Vec::new(),
            Some(exact_model_selector("child-a")),
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        let surface = dmh_trusted(&cwd, || {
            crate::engine::builtin::resolve_child_execution_surface("explore", &args)
        })
        .unwrap();
        let child = dmh_trusted(&cwd, || crate::engine::builtin::load("explore", &args)).unwrap();
        assert_eq!(surface.provider, child.model.provider_id());
        assert_eq!(surface.model, child.model.model_id_ref());
        assert_eq!(surface.config_generation, args.config.generation());
        assert_eq!(surface.tool_steering, child.tool_steering);
        assert_eq!(surface.model, "child-a");
        assert_ne!(
            surface.model,
            driver.stack[0].agent.model.model_id_ref(),
            "no root identity leaks into the surface"
        );
        assert_eq!(
            surface.tools,
            child
                .tools
                .names()
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            surface.write_authority,
            crate::engine::builtin::is_write_capable(&child)
        );
    }

    // Positive: a purely read-only noninteractive leaf is admissible. A
    // host-authored custom subagent whose entire roster is registered ordinary
    // read-only operations drives a REAL child surface (via `load`), so the
    // boolean is proven true — not against a hand-built agent. A unique name is
    // used so no built-in factory tiers extra tools onto the roster; `web` is
    // set to a command-less custom provider so the default `webfetch`/
    // `websearch` (Dynamic network tools) are not attached to the surface.
    {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({ "web": { "provider": "custom" } }),
            vec![dmh_model("local", None)],
        );
        let agents_dir = driver.cwd.join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("readonly-probe.md"),
            vnext_coding_agent_document(
                "readonly-probe",
                "read-only leaf",
                "Investigate read-only.",
            ),
        )
        .unwrap();
        write_host_tool_surface(&agents_dir, "readonly-probe", &["read"]);
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd(
            &cwd,
            false,
            Vec::new(),
            None,
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        let surface = dmh_trusted(&cwd, || {
            crate::engine::builtin::resolve_child_execution_surface("readonly-probe", &args)
        })
        .unwrap();
        assert!(
            surface.parallel_read_only_eligible,
            "a read-only leaf is admissible: {:?}",
            surface.tools
        );
        assert!(!surface.write_authority);
    }

    // False (registered-ordinary): the same read-only leaf ALSO exposes a
    // user-authored custom-bash template (`webfetch` from a `web.custom` command).
    // `approval_exempt` makes its `effect()` read `ReadOnly`, but it can run an
    // arbitrary shell command, so it is NOT a registered ordinary operation → the
    // child is NOT `parallel_read_only_eligible`.
    {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({ "web": { "provider": "custom", "custom": { "fetch_command": "echo {url}" } } }),
            vec![dmh_model("local", None)],
        );
        let agents_dir = driver.cwd.join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("readonly-probe.md"),
            vnext_coding_agent_document(
                "readonly-probe",
                "read-only leaf",
                "Investigate read-only.",
            ),
        )
        .unwrap();
        write_host_tool_surface(&agents_dir, "readonly-probe", &["read"]);
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd(
            &cwd,
            false,
            Vec::new(),
            None,
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        let surface = dmh_trusted(&cwd, || {
            crate::engine::builtin::resolve_child_execution_surface("readonly-probe", &args)
        })
        .unwrap();
        assert!(
            surface.tools.contains(&"webfetch".to_string()),
            "the custom-bash webfetch template is on the surface: {:?}",
            surface.tools
        );
        assert!(
            !surface.parallel_read_only_eligible,
            "a custom approval_exempt bash template forecloses eligibility despite a ReadOnly effect"
        );
    }

    // False: a read-only-SOUNDING child whose real surface carries a dynamic
    // tool (bash). The built-in `explore` holds `bash` (Dynamic).
    {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![dmh_model("local", None)],
        );
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd(
            &cwd,
            false,
            Vec::new(),
            None,
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        let surface = dmh_trusted(&cwd, || {
            crate::engine::builtin::resolve_child_execution_surface("explore", &args)
        })
        .unwrap();
        assert!(
            surface.tools.contains(&"bash".to_string()),
            "explore exposes a dynamic tool: {:?}",
            surface.tools
        );
        assert!(
            !surface.parallel_read_only_eligible,
            "a dynamic tool forecloses eligibility"
        );
    }

    // False: a write-capable child (granted mutating authority).
    {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![dmh_model("local", None)],
        );
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd(
            &cwd,
            false,
            Vec::new(),
            None,
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        let surface = dmh_trusted(&cwd, || {
            crate::engine::builtin::resolve_child_execution_surface("builder", &args)
        })
        .unwrap();
        assert!(surface.write_authority);
        assert!(!surface.parallel_read_only_eligible);
    }

    // False: a write-capable child (holds lock/write tools) is never a
    // parallel read-only admission candidate — regardless of nested
    // delegation. `builder` is the structural writer surface.
    {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![dmh_model("local", None)],
        );
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd(
            &cwd,
            false,
            Vec::new(),
            None,
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        let surface = dmh_trusted(&cwd, || {
            crate::engine::builtin::resolve_child_execution_surface("builder", &args)
        })
        .unwrap();
        assert!(
            surface.write_authority,
            "builder is write-capable: {:?}",
            surface.tools
        );
        assert!(
            !surface.parallel_read_only_eligible,
            "write authority forecloses parallel read-only eligibility"
        );
    }

    // The surface is the ONLY contract for concurrent admission. The batch
    // scheduler admits a child concurrently via exactly
    // `batch_child_concurrently_admissible`, driven by the child's real surface:
    // a read-only leaf is admitted; a read-only-sounding dynamic child (explore)
    // and a nested child (scout) are REFUSED concurrent admission; a
    // write-capable child keeps its (separate) parent-scoped write-admission.
    {
        let (mut driver, _tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({ "web": { "provider": "custom" } }),
            vec![dmh_model("local", None)],
        );
        let agents_dir = driver.cwd.join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("readonly-probe.md"),
            vnext_coding_agent_document(
                "readonly-probe",
                "read-only leaf",
                "Investigate read-only.",
            ),
        )
        .unwrap();
        write_host_tool_surface(&agents_dir, "readonly-probe", &["read"]);
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd(
            &cwd,
            false,
            Vec::new(),
            None,
            crate::engine::builtin::DelegationRecursionContext::default(),
        );
        // The concurrency key is `parallel_read_only_eligible` OR the child's REAL
        // parent write-admission (`is_write_capable`), never a bare `write_scope`.
        let gate = |agent: &str| -> bool {
            let (surface, write_capable) = dmh_trusted(&cwd, || {
                let surface =
                    crate::engine::builtin::resolve_child_execution_surface(agent, &args).unwrap();
                let child = crate::engine::builtin::load(agent, &args).unwrap();
                let write_capable = crate::engine::builtin::is_write_capable(&child);
                (surface, write_capable)
            });
            crate::engine::builtin::batch_child_concurrently_admissible(&surface, write_capable)
        };
        assert!(
            gate("readonly-probe"),
            "read-only leaf is concurrently admissible"
        );
        assert!(
            !gate("explore"),
            "a dynamic child is refused concurrent admission (exclusive)"
        );
        assert!(
            !gate("scout"),
            "a nested child is refused concurrent admission (exclusive)"
        );
        assert!(
            gate("builder"),
            "a write-capable child keeps its parent-scoped concurrent write-admission"
        );
    }

    // Fα: a custom/dynamic child handed a `write_scope` that did NOT pass parent
    // disjoint-scope write-admission (it has no REAL single-writer capability) is
    // NOT concurrently admissible — its surface carries `write_authority` (a scope
    // was requested), but `write_authority` is informational only. It is neither
    // `parallel_read_only_eligible` nor parent-write-admitted, so it runs
    // EXCLUSIVELY.
    {
        let (mut driver, tmp) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({ "web": { "provider": "custom", "custom": { "fetch_command": "echo {url}" } } }),
            vec![dmh_model("local", None)],
        );
        let agents_dir = driver.cwd.join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        // A custom subagent whose only non-read tool is the custom-bash `webfetch`
        // template (arbitrary shell under `approval_exempt`) — dynamic, NOT
        // write-capable in the single-writer-lock sense.
        std::fs::write(
            agents_dir.join("custom-writer.md"),
            vnext_coding_agent_document("custom-writer", "custom bash child", "Investigate."),
        )
        .unwrap();
        let scope = tmp.path().join("scope");
        std::fs::create_dir_all(&scope).unwrap();
        let cwd = driver.cwd.clone();
        let args = driver.spawn_args_delegated_in_cwd_scoped(
            &cwd,
            false,
            Vec::new(),
            None,
            crate::engine::builtin::DelegationRecursionContext::default(),
            DelegationConfinement {
                lock_identity: None,
                write_scope: Some(scope.clone()),
            },
        );
        let (surface, write_capable) = dmh_trusted(&cwd, || {
            let surface =
                crate::engine::builtin::resolve_child_execution_surface("custom-writer", &args)
                    .unwrap();
            let child = crate::engine::builtin::load("custom-writer", &args).unwrap();
            let write_capable = crate::engine::builtin::is_write_capable(&child);
            (surface, write_capable)
        });
        assert!(
            surface.write_authority,
            "a requested write_scope sets the informational write_authority flag"
        );
        assert!(
            !write_capable,
            "a custom-bash child holds no single-writer lock/write tool"
        );
        assert!(
            !surface.parallel_read_only_eligible,
            "a custom approval_exempt bash template forecloses read-only eligibility"
        );
        assert!(
            !crate::engine::builtin::batch_child_concurrently_admissible(&surface, write_capable),
            "a write_scope-only custom child that did NOT pass parent write-admission runs EXCLUSIVELY, not concurrently"
        );
    }
}

/// AC8: preflight is side-effect-free — it creates no write-scope grant (a real
/// dispatch pregrants) — and a generation change before start discards the old
/// surface rather than using stale posture.
#[tokio::test]
async fn resolved_child_execution_surface_preflight_is_side_effect_free() {
    let (mut driver, tmp) = test_driver(8);
    dmh_install_config(
        &mut driver,
        serde_json::json!({}),
        vec![dmh_model("local", None), dmh_model("child-a", None)],
    );
    let approver = install_test_approver(&mut driver);
    let scope = tmp.path().join("scope");
    std::fs::create_dir_all(&scope).unwrap();
    let cwd = driver.cwd.clone();

    // Preflight a write-scoped child. A real dispatch pregrants the scope; the
    // side-effect-free surface resolution must NOT.
    let args = driver.spawn_args_delegated_in_cwd_scoped(
        &cwd,
        false,
        Vec::new(),
        Some(exact_model_selector("child-a")),
        crate::engine::builtin::DelegationRecursionContext::default(),
        DelegationConfinement {
            lock_identity: None,
            write_scope: Some(scope.clone()),
        },
    );
    let surface = dmh_trusted(&cwd, || {
        crate::engine::builtin::resolve_child_execution_surface("builder", &args)
    })
    .unwrap();
    assert_eq!(surface.model, "child-a");
    assert!(
        surface.write_authority,
        "builder + write_scope carries write authority"
    );
    assert!(!surface.parallel_read_only_eligible);
    assert_eq!(surface.config_generation, driver.config.generation());

    // No write-scope pregrant, no approval — construction is a pure resolution.
    assert!(
        !approver
            .store()
            .is_path_granted_for(
                &scope,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite
            )
            .await,
        "preflight must not pregrant the write scope"
    );

    // A generation change before start: re-resolve from the generation that
    // actually starts. The old surface's identity is discarded, not reused.
    dmh_install_config(
        &mut driver,
        serde_json::json!({}),
        vec![dmh_model("local", None), dmh_model("child-b", None)],
    );
    let args2 = driver.spawn_args_delegated_in_cwd_scoped(
        &cwd,
        false,
        Vec::new(),
        Some(exact_model_selector("child-b")),
        crate::engine::builtin::DelegationRecursionContext::default(),
        DelegationConfinement::default(),
    );
    let surface2 = dmh_trusted(&cwd, || {
        crate::engine::builtin::resolve_child_execution_surface("builder", &args2)
    })
    .unwrap();
    assert_eq!(
        surface2.model, "child-b",
        "re-resolved from the generation that actually starts"
    );
    assert_ne!(
        surface.model, surface2.model,
        "the stale surface's identity is discarded, not reused"
    );
    assert_ne!(
        surface.config_generation, surface2.config_generation,
        "a config refresh bumps the generation the new surface is bound to"
    );

    // Drive the REAL batch admission path: read-only-sounding DYNAMIC children
    // (explore holds `bash`) are not concurrently admissible, so the scheduler
    // routes them to SERIAL execution — and BOTH still complete and are
    // collected. Gating concurrency never drops or reorders results.
    {
        let (mut driver, _tmp3) = test_driver(8);
        dmh_install_config(
            &mut driver,
            serde_json::json!({}),
            vec![dmh_model("local", None)],
        );
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        let task = BatchNoninteractiveTask {
            entries: vec![
                batch_entry("first", "explore", None),
                batch_entry("second", "explore", None),
            ],
            child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
            why: "test".to_string(),
            repair_notes: Vec::new(),
            task_call_id: "task-serial-admission".to_string(),
            task_provider_item_id: None,
            task_function_call_id: None,
        };
        let completion = driver
            .execute_batch_noninteractive_task(
                task,
                &tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            completion.children.len(),
            2,
            "both serially-admitted children are collected"
        );
        let labels: std::collections::BTreeSet<&str> = completion
            .children
            .iter()
            .map(|c| c.label.as_str())
            .collect();
        assert!(
            labels.contains("first") && labels.contains("second"),
            "both serial children produced a result: {labels:?}"
        );
    }
}

/// Run a 2-child batch of `child_agent` against a provider whose responses are
/// long-delayed, and return how many child requests are simultaneously IN FLIGHT
/// while the first child's (delayed) response is still outstanding. A
/// non-admissible (dynamic) child holds the EXCLUSIVE write guard → the second
/// cannot dispatch → 1 in flight. Concurrently-admissible (read-only) children
/// share read guards → both dispatch → 2 in flight.
///
/// The batch runs on a dedicated big-stack thread (avoiding the pre-existing
/// deep-batch stack overflow); the probe runs on THIS thread against the
/// provider's cross-thread atomic request counter using real-time sleeps, so its
/// timing is independent of the batch's scheduling. The batch is cancelled once
/// the count is read, so the long delay is never fully waited.
fn dmh_batch_in_flight_while_first_delayed(child_agent: &str, custom_read_only: bool) -> usize {
    let provider = cockpit_test_support::provider::ScriptedProvider::builder()
        .dialect(cockpit_test_support::provider::WireDialect::ChatCompletions)
        .turn(cockpit_test_support::provider::Turn::Text("done".into()))
        .with_delay(std::time::Duration::from_secs(20))
        .repeat_last()
        .start_blocking();
    let url = provider.base_url();
    let agent = child_agent.to_string();
    let cancel = tokio_util::sync::CancellationToken::new();
    let batch_cancel = cancel.clone();
    let batch_thread = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let (mut driver, _tmp) = test_driver_with_url_vnext(8, url.clone());
                    let config_dir = driver.cwd.join(".cockpit");
                    let providers_dir = config_dir.join("providers");
                    std::fs::create_dir_all(&providers_dir).unwrap();
                    // `web.provider = custom` (no commands) suppresses the default
                    // webfetch/websearch (Dynamic) so a read-only custom agent is
                    // genuinely eligible.
                    std::fs::write(
                        config_dir.join("config.json"),
                        r#"{"agent_chooses_subagent_model": true, "web": {"provider": "custom"}, "active_model": {"provider":"lmstudio","model":"local"}}"#,
                    )
                    .unwrap();
                    std::fs::write(
                        providers_dir.join("lmstudio.json"),
                        serde_json::json!({
                            "url": url,
                            "models": [{ "id": "local", "subagent_invokable": true }]
                        })
                        .to_string(),
                    )
                    .unwrap();
                    if custom_read_only {
                        let agents_dir = config_dir.join("agents");
                        std::fs::create_dir_all(&agents_dir).unwrap();
                        std::fs::write(
                            agents_dir.join("readonly-probe.md"),
                            vnext_coding_agent_document(
                                "readonly-probe",
                                "read-only leaf",
                                "Investigate read-only.",
                            ),
                        )
                        .unwrap();
                        write_host_tool_surface(&agents_dir, "readonly-probe", &["read"]);
                        admit_authored_child_to_test_grants(&mut driver, "authored/readonly-probe");
                    }
                    driver.refresh_config_from_disk_for_tests();
                    let trust_cwd = driver.cwd.clone();
                    let _trust = crate::config::trust::enter_workspace_trust_policy(
                        crate::config::trust::WorkspaceTrustPolicy {
                            root: crate::config::trust::resolve_trust_root(&trust_cwd)
                                .unwrap_or_else(|_| crate::config::trust::TrustRoot {
                                    opened_path: trust_cwd.clone(),
                                    root: trust_cwd.clone(),
                                    kind: crate::config::trust::TrustRootKind::Directory,
                                }),
                            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                        },
                    );

                    // Each batch member needs its delegation job + payload
                    // persisted so payload delivery succeeds and the child actually
                    // dispatches.
                    seed_batch_task_delegation(&driver, "task-concurrency", &["a", "b"]).await;
                    seed_task_payload(&driver, "task-concurrency", "a", &agent).await;
                    seed_task_payload(&driver, "task-concurrency", "b", &agent).await;
                    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
                    let task = BatchNoninteractiveTask {
                        entries: vec![
                            batch_entry("a", &agent, None),
                            batch_entry("b", &agent, None),
                        ],
                        child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
                        why: "test".to_string(),
                        repair_notes: Vec::new(),
                        task_call_id: "task-concurrency".to_string(),
                        task_provider_item_id: None,
                        task_function_call_id: None,
                    };
                    let _ = driver
                        .execute_batch_noninteractive_task(task, &tx, batch_cancel)
                        .await;
                })
        })
        .unwrap();

    // Probe on THIS thread (real-time, independent of the batch's scheduling).
    // Wait (generously) for the FIRST child's request to reach the provider,
    // then give a would-be-concurrent second child ample time to ALSO dispatch,
    // and read how many are in flight while the first is still delayed.
    for _ in 0..200 {
        if provider.request_count() >= 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let in_flight = provider.request_count();
    // Stop the batch early — the 20s delay is never fully waited.
    cancel.cancel();
    batch_thread.join().unwrap();
    in_flight
}

/// AC7/AC8 (non-vacuous concurrency gate): the surface's admission decision is
/// enforced by the read/write lock in the REAL batch path. A dynamic child runs
/// EXCLUSIVELY (only one request in flight while it holds the write guard); two
/// read-only-eligible children OVERLAP (both in flight under shared read guards).
/// Removing the write guard makes the dynamic case show 2 in flight → this fails.
#[test]
fn delegated_batch_admission_gate_serializes_dynamic_and_overlaps_read_only() {
    // `explore` holds `bash` (Dynamic) → not admissible → EXCLUSIVE write guard →
    // the second child is blocked → 1 in flight.
    assert_eq!(
        dmh_batch_in_flight_while_first_delayed("explore", false),
        1,
        "a dynamic (non-admissible) child runs EXCLUSIVELY: the second is blocked on the write guard"
    );
    // A read-only-eligible leaf → SHARED read guards → both children overlap → 2
    // in flight.
    assert_eq!(
        dmh_batch_in_flight_while_first_delayed("readonly-probe", true),
        2,
        "read-only-eligible children run CONCURRENTLY under shared read guards"
    );
}

/// Canned executor for the fork-inheritance test: returns a fixed token so a
/// resolved command output can be planted in the parent's cache.
struct CannedCommandExecutor(String);

#[async_trait::async_trait]
impl crate::secret_command::CommandSecretExecutor for CannedCommandExecutor {
    async fn run(
        &self,
        _argv: &[String],
    ) -> std::result::Result<String, crate::secret_command::CommandSecretError> {
        Ok(self.0.clone())
    }
}

/// Drives the REAL `prepare_fork_task_context` production path: a task fork
/// inherits the parent session's command-secret cache, so the DERIVED child's
/// store funnel injects the resolved command output. This does NOT manually set
/// the cache on the child — removing the production cache copy in
/// `prepare_fork_task_context` leaves the child cache-less and the token
/// un-redacted, failing this test.
#[tokio::test]
async fn forked_task_session_inherits_command_secret_cache_via_real_path() {
    let (driver, _tmp) = test_driver_without_network(1);

    // Plant a command spec in the parent session's vault and a cache that has
    // already resolved it (as `start_worker` would before a fork).
    let mut store =
        crate::credentials::CredentialStore::from_vault(driver.session.secret_vault().clone())
            .unwrap();
    store
        .set_named_secret_command("forkcmd", vec!["prog".to_string()])
        .unwrap();
    store.save().unwrap();

    let token = "forked-task-inherited-token-abcdef0123456789";
    let cache = crate::secret_command::CommandSecretCache::new(std::sync::Arc::new(
        CannedCommandExecutor(token.to_string()),
    ));
    cache
        .ensure_resolved("forkcmd", &["prog".to_string()])
        .await;
    driver.session.set_command_secret_cache(Some(cache));

    // Real production derivation — NOT a manual child cache install.
    let (child, _history) = driver
        .prepare_fork_task_context()
        .await
        .expect("fork task context");

    // The child's store funnel injects the inherited resolved output, so the
    // redaction table (built the way the worker builds it) redacts the token.
    let table = crate::redact::RedactionTable::build_with_env_and_credential_store(
        &crate::config::extended::ExtendedConfig::default().redact,
        &child.project_root,
        &std::collections::HashMap::new(),
        &child.credential_store().unwrap(),
    )
    .unwrap();
    assert_ne!(
        table.scrub(token),
        token,
        "the forked child must inherit the parent's command-secret cache via \
         prepare_fork_task_context"
    );
}

#[tokio::test]
async fn forked_task_session_inherits_process_containment_via_real_path() {
    // A forked task session's lifecycle hooks must run under the parent's
    // containment handle; if `prepare_fork_task_context` omitted the copy the
    // child would get `None` and every hook would silently fail open as
    // `descendant_containment_unsupported` once a real broker lands.
    let (driver, _tmp) = test_driver_without_network(1);
    let actor = crate::process_containment::ProcessContainmentActor::start(
        driver.session.db.clone(),
        std::sync::Arc::new(crate::process_containment::FakeProvenAdapter::new(
            crate::process_containment::PlatformKind::Fake,
        )),
    );
    driver.session.set_process_containment(Some(actor.handle()));

    // Real production derivation — NOT a manual child handle install.
    let (child, _history) = driver
        .prepare_fork_task_context()
        .await
        .expect("fork task context");

    assert!(
        child.process_containment().is_some(),
        "the forked child must inherit the parent's containment handle via \
         prepare_fork_task_context"
    );
}

// ---------------------------------------------------------------------------
// Noninteractive subagent lifecycle observe-hook boundary wiring
// (subagentStart / subagentStop). These drive the REAL driver production
// boundaries for the NONINTERACTIVE (background delegation) modes:
//   - START at `register_running` inside
//     `run_single_noninteractive_task_backgroundable` (and the batch analogue).
//   - STOP at delegation delivery inside
//     `finalize_background_noninteractive_completion` (single + batch, inline +
//     background + runtime-error paths).
// The hook command is unresolvable so it fails open (executable-not-found)
// WITHOUT spawning a process; a `hook_run` row is still recorded — the wiring
// signal (`vec!["failed"]`). On dead-code HEAD (no wiring) no such row exists.
// ---------------------------------------------------------------------------

/// Swap in a hook registry while PRESERVING the driver's resolved providers /
/// extended config (unlike `inject_hooks`, which drops providers). The single
/// delegation preflight resolves the child model from `providers`, so it must
/// stay intact for the START boundary (`register_running`) to be reached.
fn inject_hooks_keep_config(
    driver: &mut Driver,
    reg: crate::config::extended::hooks::HookRegistry,
) {
    let mut snapshot = (*driver.config.snapshot()).clone();
    snapshot.hooks = reg;
    driver
        .set_config_handle(crate::daemon::session_worker::SessionConfigHandle::detached(snapshot));
}

#[tokio::test]
async fn noninteractive_single_delivery_fires_one_paired_subagent_stop() {
    // UNIFIED dispatch: an inline single-delegation completion delivered through
    // `finalize_background_noninteractive_completion` fires exactly one
    // `subagentStop` (through the `run_stop_hooks` G::Stop dispatcher, terminal —
    // a delivered noninteractive child has already terminated), matched on the
    // child agent type. This is the pair of the `subagentStart` fired at
    // register-running.
    let (mut driver, _tmp) = test_driver(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "explore",
        ),
    );
    seed_task_delegation(&driver, "task-nis-stop", "default").await;
    driver.noninteractive_delegations.register_running(
        "task-nis-stop",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver.noninteractive_jobs.insert(
        "task-nis-stop".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {}),
        },
    );
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-nis-stop".to_string(),
                task_provider_item_id: None,
                task_function_call_id: Some("fn-nis-stop".to_string()),
                result: Box::new(Ok(single_noninteractive_completion(
                    "task-nis-stop",
                    "single report",
                ))),
            }),
            &tx,
        )
        .await
        .unwrap();
    assert!(matches!(
        delivery,
        NoninteractiveCompletionDelivery::Inline(_)
    ));
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "delivering a single noninteractive child must fire exactly one subagentStop"
    );
    drop(tx);
    while rx.recv().await.is_some() {}

    // A different-agent-type hook must NOT fire on an `explore` child delivery.
    let (mut driver, _tmp) = test_driver(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "builder",
        ),
    );
    seed_task_delegation(&driver, "task-nis-stop2", "default").await;
    driver.noninteractive_delegations.register_running(
        "task-nis-stop2",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver.noninteractive_jobs.insert(
        "task-nis-stop2".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {}),
        },
    );
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let _ = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-nis-stop2".to_string(),
                task_provider_item_id: None,
                task_function_call_id: Some("fn-nis-stop2".to_string()),
                result: Box::new(Ok(single_noninteractive_completion(
                    "task-nis-stop2",
                    "single report",
                ))),
            }),
            &tx,
        )
        .await
        .unwrap();
    assert!(
        observe_hook_events(&driver, "subagentStop")
            .await
            .is_empty(),
        "a builder-only hook must not fire on an explore child delivery"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn noninteractive_started_child_runtime_error_still_fires_one_stop() {
    // A started child whose background task returned `Err` (a runtime-level
    // delegation failure) is delivered through the error arm of
    // `finalize_background_noninteractive_completion`; it must STILL fire exactly
    // one `subagentStop` so every register-running `subagentStart` is paired.
    let (mut driver, _tmp) = test_driver(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "explore",
        ),
    );
    driver.noninteractive_delegations.register_running(
        "task-nis-err",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver.noninteractive_jobs.insert(
        "task-nis-err".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {}),
        },
    );
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let _ = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-nis-err".to_string(),
                task_provider_item_id: None,
                task_function_call_id: Some("fn-nis-err".to_string()),
                result: Box::new(Err(anyhow::anyhow!("child crashed"))),
            }),
            &tx,
        )
        .await
        .unwrap();
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "a runtime-errored started child must still fire exactly one subagentStop"
    );
}

#[tokio::test]
async fn noninteractive_batch_delivery_fires_one_subagent_stop_per_child() {
    // UNIFIED dispatch: a three-child batch completion delivered through
    // `finalize_background_noninteractive_completion` fires exactly one
    // `subagentStop` PER started child (through the `run_stop_hooks` G::Stop
    // dispatcher, terminal), all matched on the child agent type, pairing the
    // three per-entry `subagentStart`s.
    let (mut driver, _tmp) = test_driver(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "explore",
        ),
    );
    seed_batch_task_delegation(&driver, "task-nis-batch", &["first", "second", "third"]).await;
    for label in ["first", "second", "third"] {
        driver.noninteractive_delegations.register_running(
            "task-nis-batch",
            label,
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
    }
    driver.noninteractive_jobs.insert(
        "task-nis-batch".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {}),
        },
    );
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let _ = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Batch {
                task_call_id: "task-nis-batch".to_string(),
                task_provider_item_id: None,
                task_function_call_id: Some("fn-nis-batch".to_string()),
                result: Box::new(Ok(BatchNoninteractiveCompletion {
                    task_call_id: "task-nis-batch".to_string(),
                    task_provider_item_id: None,
                    task_function_call_id: Some("fn-nis-batch".to_string()),
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
                    already_terminal_labels: std::collections::BTreeSet::new(),
                })),
            }),
            &tx,
        )
        .await
        .unwrap();
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await.len(),
        3,
        "delivering a three-child batch must fire exactly one subagentStop per child"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn noninteractive_real_spawn_fires_one_subagent_start() {
    // Drive the REAL backgroundable entry point through to `register_running`: a
    // valid single delegation (child model resolves) reaches the register-running
    // boundary and fires exactly one `subagentStart` matched on the child agent
    // type. The user queue is pre-closed so the wrapper returns immediately after
    // the child is spawned (via the input arm) without waiting on the child's
    // completion.
    let (mut driver, _tmp) = test_driver_without_network(8);
    inject_hooks_keep_config(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "explore",
        ),
    );
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    queue.close().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let task = single_task(&driver, "explore", "task-start-real", None, None);
    let _ = driver
        .run_single_noninteractive_task_backgroundable(
            task,
            &queue,
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    // Reaching register_running is the START precondition: the child is live.
    assert!(
        driver
            .noninteractive_delegations
            .is_live("task-start-real", "default"),
        "a valid delegation must register the running child (START precondition)"
    );
    assert_eq!(
        observe_hook_events(&driver, "subagentStart").await,
        vec!["failed".to_string()],
        "a real noninteractive child spawn must fire exactly one subagentStart"
    );
    drop(tx);
    while rx.recv().await.is_some() {}

    // A different-agent-type hook must NOT fire on an `explore` child spawn.
    let (mut driver, _tmp) = test_driver_without_network(8);
    inject_hooks_keep_config(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "builder",
        ),
    );
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    queue.close().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let task = single_task(&driver, "explore", "task-start-real2", None, None);
    let _ = driver
        .run_single_noninteractive_task_backgroundable(
            task,
            &queue,
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        observe_hook_events(&driver, "subagentStart")
            .await
            .is_empty(),
        "a builder-only hook must not fire on an explore child spawn"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn noninteractive_prespawn_refusal_fires_neither_start_nor_stop() {
    // A child refused BEFORE it starts (an unknown child agent fails the
    // fail-closed preflight, which returns before `register_running`) must fire
    // NEITHER a subagentStart NOR a subagentStop — no child existed.
    let (mut driver, _tmp) = test_driver_without_network(8);
    inject_hooks_keep_config(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "no-such-agent",
        ),
    );
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let task = single_task(&driver, "no-such-agent", "task-refused", None, None);
    let message = driver
        .run_single_noninteractive_task_backgroundable(
            task,
            &queue,
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    // The wrapper returned a content-safe error (not a real child report).
    assert_eq!(tool_result_id(&message), "task-refused");
    // No child was ever registered running (register_running not reached).
    assert!(
        !driver
            .noninteractive_delegations
            .is_live("task-refused", "default"),
        "a fail-closed preflight registers no running child"
    );
    assert!(
        observe_hook_events(&driver, "subagentStart")
            .await
            .is_empty(),
        "a refused-before-spawn child must fire NO subagentStart"
    );
    assert!(
        observe_hook_events(&driver, "subagentStop")
            .await
            .is_empty(),
        "a refused-before-spawn child must fire NO subagentStop"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[test]
fn noninteractive_end_reason_maps_terminal_status() {
    // The single-sourced `endReason` vocabulary: each terminal registry status
    // maps to its own distinct token; a non-terminal status uses the caller's
    // fallback. Built from independent literals so a wrong mapping is rejected.
    assert_eq!(
        noninteractive_end_reason(NoninteractiveDelegationStatus::Completed, "fallback"),
        "completed"
    );
    assert_eq!(
        noninteractive_end_reason(NoninteractiveDelegationStatus::Failed, "fallback"),
        "failed"
    );
    assert_eq!(
        noninteractive_end_reason(NoninteractiveDelegationStatus::Cancelled, "fallback"),
        "cancelled"
    );
    assert_eq!(
        noninteractive_end_reason(NoninteractiveDelegationStatus::Lost, "fallback"),
        "lost"
    );
    // Non-terminal (never `complete()`d) → caller fallback, not a fabricated token.
    assert_eq!(
        noninteractive_end_reason(NoninteractiveDelegationStatus::Running, "failed"),
        "failed"
    );
    assert_eq!(
        noninteractive_end_reason(NoninteractiveDelegationStatus::Backgrounded, "aborted"),
        "aborted"
    );
}

#[tokio::test]
async fn noninteractive_whole_job_cancel_fires_one_cancelled_subagent_stop() {
    // Whole-job cancel aborts the background job so it never reaches the delivery
    // funnel; the started child must STILL fire exactly one `subagentStop`
    // (endReason `cancelled`) at the cancel boundary so no start is left unpaired.
    let (mut driver, _tmp) = test_driver(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "explore",
        ),
    );
    seed_task_delegation(&driver, "task-cancel-hook", "default").await;
    driver.noninteractive_delegations.register_running(
        "task-cancel-hook",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver.noninteractive_jobs.insert(
        "task-cancel-hook".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {
                std::future::pending::<()>().await;
            }),
        },
    );

    let body = driver
        .dispatch_task_control(
            TaskControlAction::Cancel,
            Some("task-cancel-hook".to_string()),
            None,
            None,
        )
        .await;
    assert!(body.contains("cancelled"), "{body}");
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "a whole-job cancel of a started child must fire exactly one subagentStop"
    );
}

#[tokio::test]
async fn noninteractive_redelivered_completion_does_not_double_fire_stop() {
    // The delivered-transition claim makes the paired stop fire exactly once: a
    // second delivery of the same job (already delivered) is a no-op and fires no
    // additional stop.
    let (mut driver, _tmp) = test_driver(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "explore",
        ),
    );
    seed_task_delegation(&driver, "task-redeliver", "default").await;
    driver.noninteractive_delegations.register_running(
        "task-redeliver",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver.noninteractive_jobs.insert(
        "task-redeliver".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {}),
        },
    );
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    for _ in 0..2 {
        let _ = driver
            .finalize_background_noninteractive_completion(
                Some(BackgroundNoninteractiveCompletion::Single {
                    task_call_id: "task-redeliver".to_string(),
                    task_provider_item_id: None,
                    task_function_call_id: Some("fn-redeliver".to_string()),
                    result: Box::new(Ok(single_noninteractive_completion(
                        "task-redeliver",
                        "single report",
                    ))),
                }),
                &tx,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "a re-delivered completion must not fire a second subagentStop"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn noninteractive_batch_real_spawn_fires_one_start_per_entry() {
    // Drive the REAL batch backgroundable entry point through the per-entry
    // `register_running` loop: two valid entries fire exactly two `subagentStart`
    // hooks (one per started child). The user queue is pre-closed so the wrapper
    // returns right after spawning without waiting on the children.
    let (mut driver, _tmp) = test_driver_without_network(8);
    inject_hooks_keep_config(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "explore",
        ),
    );
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    queue.close().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let task = BatchNoninteractiveTask {
        entries: vec![
            batch_entry("first", "explore", None),
            batch_entry("second", "explore", None),
        ],
        child_cwds: vec![root_child_cwd(&driver), root_child_cwd(&driver)],
        why: "test".to_string(),
        repair_notes: Vec::new(),
        task_call_id: "task-batch-start".to_string(),
        task_provider_item_id: None,
        task_function_call_id: None,
    };
    let _ = driver
        .run_batch_noninteractive_task_backgroundable(
            task,
            &queue,
            &tx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        driver
            .noninteractive_delegations
            .is_live("task-batch-start", "first")
            && driver
                .noninteractive_delegations
                .is_live("task-batch-start", "second"),
        "a valid batch registers both running children (START precondition)"
    );
    assert_eq!(
        observe_hook_events(&driver, "subagentStart").await.len(),
        2,
        "a real batch spawn must fire exactly one subagentStart per started child"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}
