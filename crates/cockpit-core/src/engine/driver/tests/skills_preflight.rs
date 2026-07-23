use super::*;

/// Seeds re-execute in the caller's cwd and land as native tool-call/
/// result pairs folded into the task turn; oversized seeds are dropped
/// under the budget and truncation is reported.
#[tokio::test]
async fn inject_seeds_caps_under_budget_and_injects_pairs() {
    let (mut driver, tmp) = driver_with_read_caller();
    // A small file (fits) followed by several sizeable ones. Each
    // sizeable file is ~1.5K tokens of distinct lines; the shared 2K-token
    // seed budget admits the small one, then trips before all the big ones
    // fit — so at least one whole seed is dropped, deterministically.
    let small = tmp.path().join("small.txt");
    std::fs::write(&small, "hello\n").unwrap();
    let mut big_paths = Vec::new();
    for i in 0..3 {
        let p = tmp.path().join(format!("big{i}.txt"));
        // ~600 short, distinct lines → comfortably above ~1K tokens each.
        let body: String = (0..600).map(|n| format!("file{i} line {n}\n")).collect();
        std::fs::write(&p, body).unwrap();
        big_paths.push(p);
    }

    // The caller's last turn is the `task` call the delegation came from.
    let task_call_id = "task-1";
    driver.stack[0].history = vec![
        Message::user("please investigate"),
        assistant_with_task_call(task_call_id),
    ];

    let mut seeds = vec![SeedTool {
        tool: "read".into(),
        args: serde_json::json!({ "path": small.to_string_lossy() }),
    }];
    for p in &big_paths {
        seeds.push(SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": p.to_string_lossy() }),
        });
    }

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let truncated = driver.inject_seeds(&seeds, task_call_id, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // The cumulative seed output blew the 2K budget → truncation reported,
    // at least one whole seed dropped.
    assert!(truncated, "oversized seeds should trip the budget");

    let history = &driver.stack[0].history;
    // The task turn now carries the original task call PLUS exactly one
    // seed tool call (the small read); the big one was dropped whole.
    let last_assistant = history
        .iter()
        .rev()
        .find_map(|m| match m {
            Message::Assistant { content, .. } => Some(content),
            _ => None,
        })
        .unwrap();
    use crate::engine::message::AssistantContent;
    let tool_calls: Vec<_> = last_assistant
        .iter()
        .filter_map(|c| match c {
            AssistantContent::ToolCall(tc) => Some(tc.function.name.clone()),
            _ => None,
        })
        .collect();
    assert!(
        tool_calls.iter().any(|n| n == "task"),
        "task call preserved"
    );
    let seed_calls = tool_calls.iter().filter(|n| *n == "read").count();
    // At least the small seed fit, and at least one big seed was dropped
    // (so fewer than the 4 requested were folded in).
    assert!(seed_calls >= 1, "in-budget seeds folded in");
    assert!(seed_calls < seeds.len(), "an over-budget seed was dropped");
    let seed_call_ids: Vec<_> = last_assistant
        .iter()
        .filter_map(|c| match c {
            AssistantContent::ToolCall(tc) if tc.function.name == "read" => {
                Some((tc.id.clone(), tc.call_id.clone()))
            }
            _ => None,
        })
        .collect();
    for (id, call_id) in &seed_call_ids {
        assert!(id.starts_with("fc-seed-"), "seed call id is tagged");
        assert_eq!(
            call_id.as_deref(),
            Some(id.as_str()),
            "seed ToolCall.call_id uses the Cockpit synthetic provider id"
        );
    }

    // Each folded seed call has exactly one matching tool_result pair.
    use rig::message::UserContent;
    let seed_results: Vec<_> = history
        .iter()
        .filter_map(|m| match m {
            Message::User { content } => Some(content),
            _ => None,
        })
        .flat_map(|content| content.iter())
        .filter_map(|c| match c {
            UserContent::ToolResult(result) if result.id.starts_with("fc-seed-") => {
                Some((result.id.clone(), result.call_id.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        seed_results.len(),
        seed_calls,
        "one result pair per folded seed"
    );
    for (id, call_id) in &seed_results {
        assert_eq!(
            call_id.as_deref(),
            Some(id.as_str()),
            "seed ToolResult.call_id matches the synthetic provider id"
        );
    }

    // Each folded seed is also persisted as a tool-call audit row (GOALS
    // §14) so it survives in a session export, not just the live stream.
    // A seed is emitted verbatim → `wire == original`, no recovery.
    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .await
        .unwrap();
    let seed_rows: Vec<_> = rows.iter().filter(|r| r.tool == "read").collect();
    assert_eq!(
        seed_rows.len(),
        seed_calls,
        "each folded seed has a persisted tool-call row"
    );
    for r in seed_rows {
        assert!(
            r.call_id.starts_with("fc-seed-"),
            "seed row tagged as a seed"
        );
        assert_eq!(r.provider_item_id.as_deref(), Some(r.call_id.as_str()));
        assert_eq!(r.provider_call_id.as_deref(), Some(r.call_id.as_str()));
        assert_eq!(
            r.provider_call_id_source.as_deref(),
            Some("synthetic_from_cockpit_call_id")
        );
        assert_eq!(r.wire_api.as_deref(), Some("completions"));
        assert_eq!(r.provider_family.as_deref(), Some("cockpit"));
        assert_eq!(
            r.wire_input_json, r.original_input_json,
            "a seed is verbatim: wire == original (GOALS §14)"
        );
        assert_eq!(r.recovery, crate::db::tool_calls::Recovery::Clean);
    }
}

/// A seed naming a tool the caller doesn't hold (or a non-read-only tool)
/// is skipped — `inject_seeds` never dispatches a write/unknown path.
#[tokio::test]
async fn inject_seeds_skips_tools_the_caller_lacks() {
    let (mut driver, _t) = driver_with_read_caller();
    let task_call_id = "task-1";
    driver.stack[0].history = vec![assistant_with_task_call(task_call_id)];
    // `outline` is read-only but the caller (read-only `read` toolbox)
    // doesn't hold it → skipped; nothing is folded in.
    let seeds = vec![SeedTool {
        tool: "outline".into(),
        args: serde_json::json!({ "path": "/x.rs" }),
    }];
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let _ = driver.inject_seeds(&seeds, task_call_id, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    // History unchanged: only the original task turn remains.
    assert_eq!(driver.stack[0].history.len(), 1);
}

/// Read-only pre-seeds re-execute in the CHILD's cwd and become a native
/// assistant-tool-call + matching tool_result prefix for the child's
/// initial history — supporting any read-only tool, not just `read`.
#[tokio::test]
async fn prefill_child_seeds_injects_native_pairs_in_child_cwd() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());

    let child_dir = tmp.path().join("child-cwd");
    std::fs::create_dir(&child_dir).unwrap();
    let f = child_dir.join("hello.txt");
    std::fs::write(&f, "hello from the child cwd\n").unwrap();

    let seeds = vec![SeedTool {
        tool: "read".into(),
        args: serde_json::json!({ "path": "hello.txt" }),
    }];
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let (prefix, truncated) = driver
        .prefill_child_seeds(&seeds, &child, &child_dir, Some(&tx))
        .await;
    drop(tx);
    while rx.recv().await.is_some() {}

    assert!(!truncated, "one small seed fits the budget");
    // One assistant turn carrying the read call, then one tool_result.
    assert_eq!(prefix.len(), 2, "assistant call turn + tool_result");
    use crate::engine::message::AssistantContent;
    let calls: Vec<_> = match &prefix[0] {
        Message::Assistant { content, .. } => content
            .iter()
            .filter_map(|c| match c {
                AssistantContent::ToolCall(tc) => {
                    Some((tc.function.name.clone(), tc.id.clone(), tc.call_id.clone()))
                }
                _ => None,
            })
            .collect(),
        _ => panic!("first prefix message is an assistant turn"),
    };
    assert_eq!(calls.len(), 1, "the read seed became one native call");
    assert_eq!(calls[0].0, "read");
    assert_eq!(
        calls[0].2.as_deref(),
        Some(calls[0].1.as_str()),
        "prefill seed ToolCall.call_id uses the synthetic provider id"
    );
    use rig::message::{ToolResultContent, UserContent};
    match &prefix[1] {
        Message::User { content } => {
            let result = content
                .iter()
                .find_map(|c| match c {
                    UserContent::ToolResult(tr) => Some(tr),
                    _ => None,
                })
                .expect("prefill seed tool_result");
            assert_eq!(result.id, calls[0].1);
            assert_eq!(
                result.call_id.as_deref(),
                Some(calls[0].1.as_str()),
                "prefill seed ToolResult.call_id matches the synthetic provider id"
            );
            let got = result.content.iter().any(|rc| {
                matches!(
                    rc,
                    ToolResultContent::Text(t) if t.text.contains("hello from the child cwd")
                )
            });
            assert!(
                got,
                "the result carries the file body read in the child cwd"
            );
        }
        _ => panic!("second prefix message is the tool_result"),
    }
    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|row| row.call_id == calls[0].1)
        .expect("prefill seed audit row");
    assert_eq!(row.provider_call_id.as_deref(), Some(row.call_id.as_str()));
    assert_eq!(
        row.provider_call_id_source.as_deref(),
        Some("synthetic_from_cockpit_call_id")
    );
}

/// A write/lock seed is never executed — the execution-time read-only gate
/// (same rule as `seed.rs`) drops it, so nothing is injected.
#[tokio::test]
async fn prefill_child_seeds_never_executes_a_write_seed() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let target = tmp.path().join("must_not_exist.txt");
    // A write seed (even though the child holds `writeunlock`): rejected at
    // the read-only gate, never dispatched.
    let seeds = vec![SeedTool {
        tool: "writeunlock".into(),
        args: serde_json::json!({ "path": target.to_string_lossy(), "content": "x" }),
    }];
    let (prefix, _truncated) = driver
        .prefill_child_seeds(&seeds, &child, tmp.path(), None)
        .await;
    assert!(prefix.is_empty(), "a write seed injects nothing");
    assert!(!target.exists(), "a write seed is never executed");
}

/// A seed that fails to execute in the child's cwd (missing path) is
/// surfaced as a failed seed — its `Error:` body is injected as the
/// tool_result — not a hard abort of the delegation.
#[tokio::test]
async fn prefill_child_seeds_surfaces_a_failed_seed_without_aborting() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let good = tmp.path().join("ok.txt");
    std::fs::write(&good, "fine\n").unwrap();
    let missing = tmp.path().join("nope.txt");
    let seeds = vec![
        SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": missing.to_string_lossy() }),
        },
        SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": good.to_string_lossy() }),
        },
    ];
    let (prefix, _truncated) = driver
        .prefill_child_seeds(&seeds, &child, tmp.path(), None)
        .await;
    // Both seeds are injected: the failed one carries an `Error:` body, the
    // good one carries its content — the run is not aborted.
    use crate::engine::message::AssistantContent;
    let n_calls = match &prefix[0] {
        Message::Assistant { content, .. } => content
            .iter()
            .filter(|c| matches!(c, AssistantContent::ToolCall(_)))
            .count(),
        _ => panic!("assistant turn expected"),
    };
    assert_eq!(n_calls, 2, "both seeds injected (failed + ok)");
    let bodies: String = prefix
        .iter()
        .skip(1)
        .filter_map(|m| match m {
            Message::User { content } => Some(
                content
                    .iter()
                    .filter_map(|c| match c {
                        rig::message::UserContent::ToolResult(tr) => Some(
                            tr.content
                                .iter()
                                .filter_map(|rc| match rc {
                                    rig::message::ToolResultContent::Text(t) => {
                                        Some(t.text.clone())
                                    }
                                    _ => None,
                                })
                                .collect::<String>(),
                        ),
                        _ => None,
                    })
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect();
    assert!(
        bodies.contains("Error:"),
        "failed seed surfaced as an error"
    );
    assert!(bodies.contains("fine"), "the good seed still executed");
}

/// Oversized pre-seeds are dropped whole under the budget and the
/// truncation flag is set so the caller appends a model-visible note.
#[tokio::test]
async fn prefill_child_seeds_caps_under_budget_and_drops_whole_entries() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let small = tmp.path().join("small.txt");
    std::fs::write(&small, "tiny\n").unwrap();
    let mut seeds = vec![SeedTool {
        tool: "read".into(),
        args: serde_json::json!({ "path": small.to_string_lossy() }),
    }];
    for i in 0..3 {
        let p = tmp.path().join(format!("big{i}.txt"));
        let body: String = (0..600).map(|n| format!("file{i} line {n}\n")).collect();
        std::fs::write(&p, body).unwrap();
        seeds.push(SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": p.to_string_lossy() }),
        });
    }
    let (prefix, truncated) = driver
        .prefill_child_seeds(&seeds, &child, tmp.path(), None)
        .await;
    assert!(truncated, "the cumulative seed output trips the budget");
    use crate::engine::message::AssistantContent;
    let n_calls = match &prefix[0] {
        Message::Assistant { content, .. } => content
            .iter()
            .filter(|c| matches!(c, AssistantContent::ToolCall(_)))
            .count(),
        _ => panic!("assistant turn expected"),
    };
    assert!(n_calls >= 1, "in-budget seeds injected");
    assert!(n_calls < seeds.len(), "at least one whole seed dropped");
}

/// Absent/empty pre-seeds behave exactly as today: nothing injected, no
/// truncation.
#[tokio::test]
async fn prefill_child_seeds_empty_is_a_noop() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let (prefix, truncated) = driver
        .prefill_child_seeds(&[], &child, tmp.path(), None)
        .await;
    assert!(prefix.is_empty());
    assert!(!truncated);
}

/// A user-issued `/<skill>` seeds a real, recorded `skill` tool call —
/// folded into history as an assistant `skill` ToolCall + its tool_result
/// (not a model-initiated call) — with the wire-vs-user split preserved
/// (`wire == original`, `Recovery::Clean`). An unknown skill records the
/// invocation with the tool's error as the result (never a silent no-op).
#[tokio::test]
async fn seed_forced_skill_records_and_folds_a_real_skill_call() {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;

    let (mut driver, _tmp) = driver_with_skill_caller();
    // A name almost certainly not on disk → the `skill` tool returns an
    // invalid-input error; the seam still records + folds the call. (Host
    // config can vary, so we assert the seam contract, not a body load —
    // body loading itself is covered by `tools::skill` tests.)
    let skill_name = "definitely-not-a-real-skill-xyz";

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.seed_forced_skill(skill_name, &tx).await;
    drop(tx);
    // A ToolStart + ToolEnd pair was streamed for the synthesized call.
    let mut tool_starts = 0;
    let mut tool_ends = 0;
    while let Some(ev) = rx.recv().await {
        match ev {
            TurnEvent::ToolStart { tool, .. } if tool == "skill" => tool_starts += 1,
            TurnEvent::ToolEnd { tool, .. } if tool == "skill" => tool_ends += 1,
            _ => {}
        }
    }
    assert_eq!(tool_starts, 1, "exactly one synthesized skill ToolStart");
    assert_eq!(tool_ends, 1, "exactly one synthesized skill ToolEnd");

    // History gained an assistant `skill` ToolCall (harness-synthesized,
    // not model-initiated) followed by its tool_result.
    let history = &driver.stack[0].history;
    let assistant_skill_call = history
        .iter()
        .find_map(|m| match m {
            Message::Assistant { content, .. } => content.iter().find_map(|c| match c {
                AssistantContent::ToolCall(tc) if tc.function.name == "skill" => Some(tc.clone()),
                _ => None,
            }),
            _ => None,
        })
        .expect("a `skill` tool call was folded in");
    let tool_result = history
        .iter()
        .find_map(|m| match m {
            Message::User { content } => content.iter().find_map(|c| match c {
                UserContent::ToolResult(result) => Some(result.clone()),
                _ => None,
            }),
            _ => None,
        })
        .expect("the skill call's tool_result was folded in");
    assert_eq!(
        assistant_skill_call.call_id.as_deref(),
        Some(assistant_skill_call.id.as_str()),
        "synthetic Responses calls use the cockpit call id as provider call id"
    );
    assert_eq!(tool_result.id, assistant_skill_call.id);
    assert_eq!(
        tool_result.call_id.as_deref(),
        Some(assistant_skill_call.id.as_str()),
        "tool_result must carry the same synthetic provider call id"
    );

    // The call is persisted as a real tool-call audit row with the
    // wire-vs-user split intact (verbatim synth → wire == original, clean).
    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .await
        .unwrap();
    let skill_rows: Vec<_> = rows.iter().filter(|r| r.tool == "skill").collect();
    assert_eq!(skill_rows.len(), 1, "one persisted skill tool-call row");
    let row = skill_rows[0];
    assert!(
        row.call_id.starts_with("fc-skillslash-"),
        "row tagged as a skill-slash invocation"
    );
    assert_eq!(row.provider_item_id.as_deref(), Some(row.call_id.as_str()));
    assert_eq!(row.provider_call_id.as_deref(), Some(row.call_id.as_str()));
    assert_eq!(
        row.provider_call_id_source.as_deref(),
        Some("synthetic_from_cockpit_call_id")
    );
    assert_eq!(row.wire_api.as_deref(), Some("completions"));
    assert_eq!(row.provider_family.as_deref(), Some("cockpit"));
    assert_eq!(
        row.wire_input_json, row.original_input_json,
        "synthesized call is verbatim: wire == original (GOALS §14)"
    );
    assert_eq!(row.recovery, crate::db::tool_calls::Recovery::Clean);
    assert_eq!(
        row.original_input_json,
        serde_json::json!({ "name": skill_name }),
        "the recorded input is the synthesized `skill` args"
    );
}

/// The wire half of the split: every auto-injected body is folded ahead of
/// the user's message in relevance order, so the model still receives them
/// (the `SkillAutoInjected` transcript rows are the user-facing half).
#[test]
fn fold_injected_skills_folds_every_body_ahead_of_the_user_message() {
    use crate::skills::auto_select::InjectedSkill;

    let skills = vec![
        InjectedSkill {
            name: "firecrawl".to_string(),
            body: "FIRECRAWL BODY".to_string(),
            reason: Some("REASON SHOULD STAY OFF WIRE".to_string()),
        },
        InjectedSkill {
            name: "deploy".to_string(),
            body: "DEPLOY BODY".to_string(),
            reason: None,
        },
    ];
    let wire = Driver::fold_injected_skills(&skills, "scrape example.com please");

    // The model still receives each body (the wire is unchanged).
    assert!(
        wire.contains("FIRECRAWL BODY"),
        "firecrawl body on the wire"
    );
    assert!(wire.contains("DEPLOY BODY"), "deploy body on the wire");
    // The reason is display-only / off-wire (GOALS §14): it must never
    // leak into the folded body the model receives.
    assert!(
        !wire.contains("REASON SHOULD STAY OFF WIRE"),
        "the auto-injection reason must stay off the wire"
    );
    // In relevance/injection order, ahead of the user's message.
    let fc = wire.find("FIRECRAWL BODY").unwrap();
    let dp = wire.find("DEPLOY BODY").unwrap();
    let um = wire.find("scrape example.com please").unwrap();
    assert!(fc < dp, "first-ranked body precedes the second");
    assert!(dp < um, "bodies precede the user's message");
    assert!(
        wire.contains("Skill `firecrawl` (auto-selected):"),
        "each body keeps its auto-selected header"
    );
}

/// No injection (the empty-selection / `Selection::None` shape) leaves the
/// user's wire text untouched — and emits no rows.
#[test]
fn fold_injected_skills_empty_returns_user_text_unchanged() {
    let wire = Driver::fold_injected_skills(&[], "just a question");
    assert_eq!(wire, "just a question");
}

#[test]
fn preflight_enabled_honors_session_override_over_config() {
    let (mut driver, _tmp) = test_driver(1);
    // No override → falls back to config (default off).
    assert!(!driver.preflight_enabled());
    // Session override wins, both directions.
    driver.preflight_override = Some(true);
    assert!(driver.preflight_enabled());
    driver.preflight_override = Some(false);
    assert!(!driver.preflight_enabled());
}

#[tokio::test]
async fn set_preflight_toggle_flips_and_broadcasts() {
    let (mut driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    // Bare toggle from the default-off effective state → on.
    driver
        .run_control(DriverControl::SetPreflight { enabled: None }, &tx)
        .await;
    assert_eq!(driver.preflight_override, Some(true));
    match rx.try_recv() {
        Ok(TurnEvent::PreflightState { enabled }) => assert!(enabled),
        other => panic!("expected PreflightState(on), got {other:?}"),
    }
    // Explicit off.
    driver
        .run_control(
            DriverControl::SetPreflight {
                enabled: Some(false),
            },
            &tx,
        )
        .await;
    assert_eq!(driver.preflight_override, Some(false));
    match rx.try_recv() {
        Ok(TurnEvent::PreflightState { enabled }) => assert!(!enabled),
        other => panic!("expected PreflightState(off), got {other:?}"),
    }
}

#[test]
fn preflight_will_run_gates_the_in_progress_signal() {
    // Drives the submit-time `PreflightStarted` event
    // (implementation note): the animated
    // indicator is added ONLY when preflight is enabled AND will actually
    // run (not a `should_skip` no-op).
    let (mut driver, _tmp) = test_driver(1);

    // Disabled → never runs, regardless of the text.
    driver.preflight_override = Some(false);
    assert!(!driver.preflight_will_run("please refactor the parser module"));
    assert!(!driver.preflight_will_run("ok"));

    // Enabled → runs on a rewritable message, skips the `should_skip` set
    // (trivial / bare ack / leading `/`).
    driver.preflight_override = Some(true);
    assert!(driver.preflight_will_run("please refactor the parser module"));
    assert!(!driver.preflight_will_run("ok"), "bare ack skips");
    assert!(!driver.preflight_will_run("/plan"), "leading slash skips");
    assert!(!driver.preflight_will_run("hi"), "trivial-length skips");
}

#[tokio::test]
async fn resolve_preflight_outcome_rewritten_sets_display_and_skill() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::Rewritten {
        cleaned: "clean body".into(),
        skill: Some("verify".into()),
    };
    let (text, display, skill) = driver
        .resolve_preflight_outcome(outcome, "raw original", None, &tx)
        .await;
    assert_eq!(text, "clean body", "model gets the cleaned body");
    assert_eq!(
        display.as_deref(),
        Some("clean body"),
        "the cleaned body drives the chip display"
    );
    assert_eq!(skill.as_deref(), Some("verify"), "mid-text skill is loaded");
}

#[tokio::test]
async fn resolve_preflight_outcome_think_stripped_cleaned_flows_to_both() {
    // The strip-`<think>` `cleaned` (what the preflight path produces with
    // the toggle ON) is what `resolve_preflight_outcome` yields for BOTH
    // wire and display — one `<think>`-free string in both places.
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::Rewritten {
        cleaned: "Refactor the parser.".into(),
        skill: None,
    };
    let (text, display, _skill) = driver
        .resolve_preflight_outcome(outcome, "raw original", None, &tx)
        .await;
    assert_eq!(text, "Refactor the parser.");
    assert_eq!(display.as_deref(), Some("Refactor the parser."));
    assert_eq!(
        Some(text.as_str()),
        display.as_deref(),
        "wire and display are the same <think>-free string"
    );
}

#[tokio::test]
async fn resolve_preflight_outcome_leading_skill_wins_over_mid_text() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::Rewritten {
        cleaned: "body".into(),
        skill: Some("mid".into()),
    };
    let (_text, _display, skill) = driver
        .resolve_preflight_outcome(outcome, "raw", Some("leading".into()), &tx)
        .await;
    assert_eq!(
        skill.as_deref(),
        Some("leading"),
        "an existing leading forced_skill takes precedence"
    );
}

#[tokio::test]
async fn resolve_preflight_outcome_guard_trip_falls_back_with_notice() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::GuardTripped {
        original: "run /build now please".into(),
    };
    let (text, display, _skill) = driver
        .resolve_preflight_outcome(outcome, "run /build now please", None, &tx)
        .await;
    assert_eq!(
        text, "run /build now please",
        "the original is sent verbatim"
    );
    assert!(display.is_none(), "no chip on a guard-tripped fallback");
    // A one-time notice is surfaced.
    match rx.try_recv() {
        Ok(TurnEvent::Notice { text }) => assert!(text.contains("preflight")),
        other => panic!("expected a preflight-skipped Notice, got {other:?}"),
    }
    // Logged at most once per driver.
    assert!(driver.preflight_guard_logged);
    let outcome2 = PreflightOutcome::GuardTripped {
        original: "another /plan now".into(),
    };
    let _ = driver
        .resolve_preflight_outcome(outcome2, "another /plan now", None, &tx)
        .await;
    assert!(
        matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the skipped notice fires at most once"
    );
}

#[tokio::test]
async fn resolve_preflight_outcome_skipped_is_byte_for_byte_original() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let (text, display, skill) = driver
        .resolve_preflight_outcome(
            PreflightOutcome::Skipped,
            "untouched original text",
            Some("s".into()),
            &tx,
        )
        .await;
    assert_eq!(text, "untouched original text");
    assert!(display.is_none(), "no chip when preflight didn't run");
    assert_eq!(skill.as_deref(), Some("s"), "forced_skill passes through");
}

/// `record_active_skill` de-dups by name, latest body wins — a re-invoked
/// or re-injected skill refreshes its seedable body rather than duplicating.
#[test]
fn record_active_skill_dedups_latest_wins() {
    let (mut driver, _tmp) = test_driver(1);
    driver.record_active_skill("release-notes", "first body");
    driver.record_active_skill("other", "x");
    driver.record_active_skill("release-notes", "refreshed body");
    // One entry per name; the latest body is what survives.
    let dp: Vec<_> = driver
        .active_skills
        .iter()
        .filter(|(n, _)| n == "release-notes")
        .collect();
    assert_eq!(dp.len(), 1, "name de-duped");
    assert_eq!(dp[0].1, "refreshed body", "latest body wins");
    // A blank name records nothing.
    driver.record_active_skill("  ", "ignored");
    assert!(
        driver
            .active_skills
            .iter()
            .all(|(n, _)| !n.trim().is_empty())
    );
}

/// A parent resolving an active skill seeds it into
/// the child. An ACTIVE skill contributes its instructions PLUS the
/// delegation framing (we are resolving skill X; it takes precedence over
/// the child's baked-in default), so the child drafts instead of
/// implementing.
#[test]
fn seed_skills_block_seeds_active_skill_with_framing() {
    let (mut driver, _tmp) = test_driver(1);
    // The release-notes skill is active in the parent's context (e.g.
    // user-invoked `/release-notes`).
    driver.record_active_skill(
        "release-notes",
        "Turn the rough change summary into release notes. Do NOT implement it.",
    );
    let block = driver.seed_skills_block(&["release-notes".to_string()], "builder");
    // Carries the skill's instructions...
    assert!(
        block.contains("release notes"),
        "block carries the skill body: {block:?}"
    );
    // ...plus the framing that this delegation is resolving the skill and
    // takes precedence over the child's default behavior.
    assert!(
        block.contains("skill `release-notes`")
            && block.contains("part of")
            && block.contains("precedence"),
        "block carries the resolving-skill framing: {block:?}"
    );
    assert!(
        block.contains("builder"),
        "framing names the delegated child: {block:?}"
    );
    // No spurious strip note when everything requested was active.
    assert!(
        !block.contains("dropped because"),
        "no strip note for an active skill: {block:?}"
    );
}

/// Host-side validation (validate, don't trust the model): a parent that
/// names a skill NOT active in its context has that seed deterministically
/// stripped, surfaced as a model-visible note — never a body conjured from
/// thin air, never a hard error.
#[test]
fn seed_skills_block_strips_non_active_skill_with_note() {
    let (mut driver, _tmp) = test_driver(1);
    // Only `release-notes` is active; `made-up` is not.
    driver.record_active_skill("release-notes", "release body");
    let block = driver.seed_skills_block(
        &["release-notes".to_string(), "made-up".to_string()],
        "builder",
    );
    // The active one is still seeded...
    assert!(
        block.contains("release body"),
        "active skill still seeded: {block:?}"
    );
    // ...and the non-active one is stripped with a model-visible note that
    // names it and explains why.
    assert!(
        block.contains("`made-up`") && block.contains("dropped because"),
        "non-active skill stripped with a visible note: {block:?}"
    );
    // The non-active skill's instructions never appear (nothing conjured).
    assert!(
        !block.contains("made-up body"),
        "a non-active skill cannot inject any body: {block:?}"
    );
}

/// Seeding is opt-in: a delegation that requests no skill seed (or only
/// blank names) produces an empty block — neither a seed nor a note.
#[test]
fn seed_skills_block_empty_when_nothing_requested() {
    let (mut driver, _tmp) = test_driver(1);
    driver.record_active_skill("release-notes", "body");
    assert!(driver.seed_skills_block(&[], "builder").is_empty());
    assert!(
        driver
            .seed_skills_block(&["   ".to_string()], "builder")
            .is_empty(),
        "blank names contribute nothing"
    );
}

/// End-to-end: a user-invoked `/<skill>` whose body loads makes that skill
/// part of the seedable set, so a later `task.skill_seed` naming it passes
/// host validation. Writes a real skill under the cwd's seeded scan dir.
#[tokio::test(flavor = "current_thread")]
async fn user_invoked_skill_enters_the_seedable_set() {
    let (mut driver, tmp) = driver_with_skill_caller();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
    // Refresh the driver's config snapshot now that the isolated home is in
    // place, so it carries the seeded default skills scan dir
    // (`engine-config-snapshot-adoption`).
    driver.refresh_config_from_disk_for_tests();
    // The seeded default scan dir `./.agents/skills` resolves against cwd
    // (= the driver's tmp root, with no config.json on disk).
    let skill_dir = tmp
        .path()
        .join(".agents")
        .join("skills")
        .join("release-notes");
    std::fs::create_dir_all(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        "---\nname: release-notes\ndescription: draft release notes\n---\nRELEASE NOTES, do not implement.",
    )
    .unwrap();

    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    driver.seed_forced_skill("release-notes", &tx).await;

    // The stored seedable body is the rendered skill body itself — the
    // `Skill \`name\`:\n\n` wrapper the skill tool prepends is stripped, so
    // the seed carries instructions, not the tool-output wrapper line.
    let stored = driver
        .active_skills
        .iter()
        .find(|(n, _)| n == "release-notes")
        .map(|(_, b)| b.as_str());
    assert_eq!(
        stored,
        Some("RELEASE NOTES, do not implement."),
        "user-invoked skill body enters the seedable set, wrapper stripped"
    );

    // The skill is now active in the parent's context, so seeding it into a
    // child succeeds and carries the loaded body.
    let block = driver.seed_skills_block(&["release-notes".to_string()], "builder");
    assert!(
        block.contains("RELEASE NOTES, do not implement."),
        "user-invoked skill body is seedable: {block:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn failed_user_invoked_skill_does_not_enter_seedable_set() {
    let (mut driver, tmp) = driver_with_skill_caller();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;

    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    driver.seed_forced_skill("missing-skill", &tx).await;

    assert!(
        driver.active_skills.is_empty(),
        "failed skill invocation must not become seedable"
    );
    let block = driver.seed_skills_block(&["missing-skill".to_string()], "builder");
    assert!(
        block.contains("dropped because they are not active"),
        "inactive failed skill should be stripped with a note: {block:?}"
    );
    assert!(
        !block.contains("Skill `missing-skill`:"),
        "failed skill should not inject a seeded skill body: {block:?}"
    );
}
