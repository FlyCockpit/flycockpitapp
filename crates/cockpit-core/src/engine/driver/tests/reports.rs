use super::*;

/// A `builder` delegation that wrote a file returns a structured envelope with
/// `files_changed` derived deterministically from its edits — not prose.
#[test]
fn builder_report_is_structured_envelope_with_host_derived_files() {
    let (driver, _tmp) = test_driver(1);
    let builder = crate::engine::builtin::load("builder", &driver.spawn_args(true)).unwrap();
    let history = vec![
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
        Message::assistant("I changed the file."),
    ];
    let deferred = crate::engine::deferred::DeferredLog::new();
    // Via the structural `return` tool: the model fields plus the host
    // ledger render together.
    let fields = serde_json::json!({
        "accomplished": "added the flag",
        "decisions_made": "used a u32",
    });
    let report = assemble_subagent_report(&builder, &history, &deferred, Some(&fields));
    assert!(report.contains("## Accomplished"));
    assert!(report.contains("added the flag"));
    assert!(report.contains("## Decisions made"));
    assert!(report.contains("## Files changed"));
    assert!(report.contains("/src/a.rs"));
    assert!(report.contains("abc123"));
}

/// A read-only `explore` delegation returns the same envelope shape with an
/// empty `files_changed` (it issued no write/edit/unlock calls), and the
/// no-return-tool fallback wraps its final text as `accomplished`.
#[test]
fn explore_report_envelope_has_empty_files_and_fallback_wraps_final_text() {
    let (driver, _tmp) = test_driver(1);
    let explore = crate::engine::builtin::load("explore", &driver.spawn_args(false)).unwrap();
    let history = vec![Message::assistant("the bug is in foo.rs line 10")];
    let deferred = crate::engine::deferred::DeferredLog::new();
    // No `return` call (fallback): final text becomes `accomplished`; no
    // files section because nothing was written.
    let report = assemble_subagent_report(&explore, &history, &deferred, None);
    assert!(report.contains("## Accomplished"));
    assert!(report.contains("the bug is in foo.rs line 10"));
    assert!(
        !report.contains("## Files changed"),
        "read-only run must not list files: {report}"
    );
}

#[test]
fn explore_deferred_items_appear_in_subagent_report() {
    let (driver, _tmp) = test_driver(1);
    let explore = crate::engine::builtin::load("explore", &driver.spawn_args(false)).unwrap();
    assert!(explore.tools.names().contains(&"defer_to_orchestrator"));
    let history = vec![Message::assistant("the assigned search is complete")];
    let deferred = crate::engine::deferred::DeferredLog::new();
    deferred.push("follow up on the unrelated config mismatch");

    let report = assemble_subagent_report(&explore, &history, &deferred, None);

    assert!(report.contains("the assigned search is complete"));
    assert!(report.contains("[deferred to orchestrator"));
    assert!(report.contains("- follow up on the unrelated config mismatch"));
    assert!(deferred.is_empty(), "report assembly drains deferred items");
}

#[test]
fn empty_deferred_log_leaves_subagent_report_unchanged() {
    let (driver, _tmp) = test_driver(1);
    let explore = crate::engine::builtin::load("explore", &driver.spawn_args(false)).unwrap();
    let history = vec![Message::assistant("the bug is in foo.rs line 10")];
    let baseline = assemble_subagent_report(
        &explore,
        &history,
        &crate::engine::deferred::DeferredLog::new(),
        None,
    );

    let report = assemble_subagent_report(
        &explore,
        &history,
        &crate::engine::deferred::DeferredLog::new(),
        None,
    );

    assert_eq!(report, baseline);
    assert!(!report.contains("[deferred to orchestrator"));
}

/// The `docs` pipeline is exempt: a `docs`-style agent holds no `return`
/// tool, so `assemble_subagent_report` returns its plain answer unchanged
/// (no envelope headers).
#[test]
fn docs_style_agent_without_return_tool_reports_plain_answer() {
    // A bare agent with an empty toolbox stands in for the `docs` answerer
    // (a pipeline stage, not an AgentDef) — it holds no `return` tool.
    let (driver, _tmp) = test_driver(1);
    let plain = Agent {
        name: "docs-answerer".into(),
        system: String::new(),
        role_prompt: String::new(),
        tools: crate::engine::tool::ToolBox::new(),
        model: driver.stack[0].agent.model.clone(),
        params: crate::engine::model::ModelParams::default(),
        scan_tool_results: false,
        llm_mode: crate::config::extended::LlmMode::default(),
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: driver.stack[0].agent.env_overlay.clone(),
    };
    let history = vec![Message::assistant("The answer is to call foo() with bar.")];
    let deferred = crate::engine::deferred::DeferredLog::new();
    let report = assemble_subagent_report(&plain, &history, &deferred, None);
    assert_eq!(report, "The answer is to call foo() with bar.");
    assert!(!report.contains("## Accomplished"));
}

#[test]
fn failed_subagent_progress_lists_partial_edits_and_incomplete_verification() {
    let history = vec![
        read_turn("r1", "/src/a.rs"),
        Message::tool_result_with_call_id("r1".to_string(), None, "[hash=old ok]"),
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
        bash_turn("b1", "cargo test -p cockpit-cli"),
    ];

    let progress = partial_progress_from_history(&history);
    assert_eq!(progress.files_read, vec!["/src/a.rs"]);
    assert_eq!(progress.files_edited[0].path, "/src/a.rs");
    assert_eq!(progress.files_edited[0].hash.as_deref(), Some("abc123"));
    assert_eq!(
        progress.verification_state.as_deref(),
        Some("not_completed")
    );
    assert_eq!(progress.review_state.as_deref(), Some("needs_review"));
    assert_eq!(progress.dirty_owned_changes, vec!["/src/a.rs"]);

    let report = render_failed_subagent_report(
        "Error: noninteractive agent `builder` exceeded 16 turns",
        &progress,
    );
    assert!(report.contains("Partial progress"));
    assert!(report.contains("`/src/a.rs`"));
    assert!(report.contains("Verification did not complete"));
    assert!(report.contains("needs_review"));
    assert!(!report.contains("before starting"));
    assert!(!report.contains("no code changes"));
}

#[test]
fn failed_subagent_before_first_tool_has_no_partial_progress() {
    let history = vec![Message::user("please edit a.rs")];
    let progress = partial_progress_from_history(&history);
    assert!(progress.is_empty());
    assert_eq!(
        render_failed_subagent_report("Error: model request failed", &progress),
        "Error: model request failed"
    );
}

#[test]
fn failed_report_renders_compact_deterministic_prose() {
    let envelope = SubagentFailureEnvelope {
        provider: "flaky".to_string(),
        model: "bad-model".to_string(),
        error_class: crate::engine::model::InferenceErrorClass::TimeoutTtft.as_str(),
        elapsed_ms: 120_000,
        fallback_tried: vec![crate::engine::agent::FailoverAttempt {
            provider: "flaky".to_string(),
            model: "bad-model".to_string(),
            error_class: Some(crate::engine::model::InferenceErrorClass::TimeoutTtft.as_str()),
            outcome: "failed",
        }],
        suggested_action: "retry_or_choose_another_model".to_string(),
        detail: "no first token".to_string(),
    };
    let progress = DelegationPartialProgress::default();
    let first = render_failed_subagent_failure(&envelope, &progress);
    let second = render_failed_subagent_failure(&envelope, &progress);
    assert_eq!(first, second);
    assert!(!first.contains('{'), "{first}");
    assert!(!first.contains('}'), "{first}");
    assert!(first.contains("Suggested action (advisory)"), "{first}");
}

#[test]
fn spawn_gate_clamps_to_ceiling_and_requires_output_dir() {
    // Depth ceiling (GOALS §24): at the ceiling the spawn is refused and
    // the branch does its own work (clamp, don't crash). Below it, the
    // child depth advances by one.
    assert_eq!(spawn_gate(0, 3, "/tmp/out"), Ok(1));
    assert_eq!(spawn_gate(2, 3, "/tmp/out"), Ok(3));
    let refused = spawn_gate(3, 3, "/tmp/out").unwrap_err();
    assert!(refused.contains("depth ceiling 3"), "{refused}");
    assert!(refused.contains("yourself"), "{refused}");
    // A ceiling of 0 refuses even the root's first spawn.
    assert!(spawn_gate(0, 0, "/tmp/out").is_err());
    // Missing `output_dir` is refused with the dedicated-folder nudge.
    let no_dir = spawn_gate(0, 3, "   ").unwrap_err();
    assert!(no_dir.contains("output_dir"), "{no_dir}");
    assert!(no_dir.contains("dedicated"), "{no_dir}");
}

#[tokio::test]
async fn set_swarm_config_threads_caps_to_authority() {
    let (mut driver, _tmp) = test_driver(8);
    driver.set_swarm_config(5, 0);
    assert_eq!(driver.swarm_max_depth, 5);
    assert_eq!(driver.swarm_max_concurrency, 0);
    // The authority received the (unlimited) cap: spawns never queue.
    for _ in 0..12 {
        assert!(
            driver
                .schedule
                .spawn_swarm(crate::engine::schedule::authority::SpawnSpec {
                    worker: crate::engine::schedule::authority::SpawnWorkerKind::Bee,
                    prompt: "s".into(),
                    output_dir: "/tmp/o".into(),
                    model: None,
                    depth: 1,
                    max_depth: 5,
                })
                .contains("scheduled")
        );
    }
    assert_eq!(driver.schedule.queued_swarm(), 0);
}

#[tokio::test]
async fn unbounded_loop_without_config_opt_in_is_rejected() {
    let (mut driver, _tmp) = test_driver(8);
    let err = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "poll", "limit": 0 }
        }))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("allowUnboundedLoops"), "{msg}");
    assert!(!driver.schedule.has_loop());
}

#[tokio::test]
async fn unbounded_loop_headless_is_rejected_even_with_config_opt_in() {
    let (mut driver, _tmp) = test_driver(8);
    driver.set_allow_unbounded_schedule_loops(true);
    let err = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "poll", "limit": 0 }
        }))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("headless"), "{msg}");
    assert!(!driver.schedule.has_loop());
}

#[tokio::test]
async fn primary_round_ceiling_zero_is_disabled() {
    let (driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    assert!(
        driver
            .primary_round_ceiling_allows_more(99, 0, &tx)
            .await
            .unwrap()
    );
    assert!(rx.try_recv().is_err(), "disabled ceiling emits no notice");
}

#[tokio::test]
async fn primary_round_ceiling_headless_stops_with_notice() {
    let (driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    assert!(
        !driver
            .primary_round_ceiling_allows_more(3, 3, &tx)
            .await
            .unwrap()
    );
    match rx.recv().await {
        Some(TurnEvent::Notice { text }) => {
            assert!(text.contains("configured limit of 3"), "{text}");
            assert!(text.contains("no interactive client"), "{text}");
        }
        other => panic!("expected notice, got {other:?}"),
    }
}

#[test]
fn subagent_report_event_data_preserves_body_for_all_writer_shapes() {
    for (child_agent, task_call_id, function_call_id, label, report, expected_source) in [
        (
            "explore",
            Some("task-single"),
            Some("fn-single"),
            "default",
            "single report",
            Some("provider"),
        ),
        (
            "reviewer",
            Some("task-batch"),
            Some("fn-batch"),
            "second",
            "batch report",
            Some("provider"),
        ),
        (
            "builder",
            Some("task-interactive"),
            Some("fn-interactive"),
            "default",
            "interactive report",
            Some("provider"),
        ),
        (
            "builder",
            Some("task-abort"),
            Some("fn-abort"),
            "default",
            "Error: cancelled by user",
            Some("provider"),
        ),
        (
            "builder",
            Some("task-synthetic"),
            None,
            "default",
            "Error: failed without provider identity",
            Some("synthetic_from_cockpit_call_id"),
        ),
        ("builder", None, None, "default", "detached report", None),
    ] {
        let data = subagent_report_event_data(
            child_agent,
            task_call_id,
            function_call_id,
            label,
            report,
            None,
        );
        assert_eq!(data["child_agent"], child_agent);
        assert_eq!(data["task_call_id"], serde_json::json!(task_call_id));
        assert_eq!(data["label"], label);
        assert_eq!(data["report"], report);
        match (task_call_id, function_call_id, expected_source) {
            (Some(task_call_id), Some(function_call_id), Some("provider")) => {
                assert_eq!(data["provider_call_id"], function_call_id);
                assert_eq!(data["provider_call_id_source"], "provider");
                assert_eq!(data["provider_identity"]["cockpit_call_id"], task_call_id);
                assert_eq!(
                    data["provider_identity"]["provider_call_id"],
                    function_call_id
                );
            }
            (Some(task_call_id), None, Some("synthetic_from_cockpit_call_id")) => {
                assert_eq!(data["provider_call_id"], task_call_id);
                assert_eq!(
                    data["provider_call_id_source"],
                    "synthetic_from_cockpit_call_id"
                );
                assert_eq!(data["provider_identity"]["provider_call_id"], task_call_id);
            }
            (None, None, None) => {
                assert!(data["provider_call_id"].is_null());
                assert!(data["provider_call_id_source"].is_null());
                assert!(data["provider_identity"].is_null());
            }
            other => panic!("uncovered test shape: {other:?}"),
        }
    }
}

#[test]
fn subagent_report_event_data_includes_partial_progress_when_present() {
    let progress = partial_progress_from_history(&[
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
    ]);
    let report = render_failed_subagent_report("Error: turn limit", &progress);

    let data = subagent_report_event_data(
        "builder",
        Some("task-single"),
        Some("fn-single"),
        "default",
        &report,
        Some(&progress),
    );

    assert_eq!(data["report"], report);
    assert_eq!(
        data["partial_progress"]["files_edited"][0]["path"],
        "/src/a.rs"
    );
    assert_eq!(
        data["partial_progress"]["verification_state"],
        "not_completed"
    );
    assert_eq!(data["partial_progress"]["review_state"], "needs_review");
    assert_eq!(
        data["partial_progress"]["dirty_owned_changes"][0],
        "/src/a.rs"
    );
}
