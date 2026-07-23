use super::*;

#[tokio::test]
async fn dispatch_loop_start_and_cancel() {
    let (mut driver, _tmp) = test_driver(8);
    let out = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "poll", "limit": 2 }
        }))
        .await
        .unwrap();
    assert!(out.starts_with("started loop"), "got {out}");
    assert!(driver.schedule.has_loop());
    // The capability hint for loop.cancel fires exactly once.
    let hints = driver.pending_capability_hints();
    assert_eq!(hints.len(), 1);
    assert!(hints[0].contains("loop.cancel"));
    assert!(
        driver.pending_capability_hints().is_empty(),
        "hint is one-shot"
    );

    let job_id = out
        .split('`')
        .nth(1)
        .expect("job id in backticks")
        .to_string();
    let cancel = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.cancel",
            "args": { "job_id": job_id }
        }))
        .await
        .unwrap();
    assert!(cancel.starts_with("cancelled"), "got {cancel}");
    assert!(!driver.schedule.has_loop());
}

/// End-to-end gate (implementation note): a
/// `loop.start` whose `interval` AND `limit` are JSON strings (the
/// observed weak-model failure, session `ezhcf7`) must SUCCEED — both
/// coerced/accepted, the loop scheduled — rather than erroring on a
/// value-vs-type confusion.
#[tokio::test]
async fn dispatch_loop_start_coerces_stringified_numerics_e2e() {
    let (mut driver, _tmp) = test_driver(8);
    let dispatch = driver
        .dispatch_schedule_action_repaired(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": "20000", "limit": "1", "prompt": "echo hello" }
        }))
        .await
        .expect("stringified numerics must be coerced, not rejected");
    // `limit=1` → a timer was scheduled.
    assert!(
        dispatch.output.starts_with("started timer"),
        "got {}",
        dispatch.output
    );
    assert!(driver.schedule.has_loop());

    // §14 wire-vs-user split: the row records the per-action repair as
    // its recovery, and the repaired `wire_args` show the coerced int.
    assert!(matches!(
        dispatch.recovery,
        crate::db::tool_calls::Recovery::ShapeRepair {
            stage: "parse_stringified_number",
            ..
        }
    ));
    assert_eq!(dispatch.wire_args["args"]["limit"], serde_json::json!(1));
    // The string interval (a schema-valid union member) survives as the
    // 20000-second value the parser read.
    assert_eq!(dispatch.wire_args["action"], "loop.start");
}

#[tokio::test(start_paused = true)]
async fn schedule_loop_limit_stringified_over_ceiling_is_rejected() {
    let (mut driver, _tmp) = test_driver(8);
    let result = driver
        .dispatch_schedule_action_repaired(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": "20000", "limit": "1000", "prompt": "echo hello" }
        }))
        .await;
    let err = match result {
        Ok(_) => panic!("expected over-ceiling limit to be rejected"),
        Err(error) => error.to_string(),
    };

    assert!(err.contains("1000"), "{err}");
    assert!(err.contains("100"), "{err}");
    assert!(err.contains("limit: 0"), "{err}");
    assert!(err.contains("approval"), "{err}");
    assert!(!driver.schedule.has_loop());
}

/// The §14 record is populated on the persisted `tool_call` row exactly
/// like a top-level tool repair: a stringified-numeric `schedule` call stores
/// `recovery_kind=shape_repair`/`recovery_stage=parse_stringified_number`,
/// `original_input` = what the model sent, `wire_input` = the repaired
/// `{action, args}`. Drives the production dispatch + record path.
#[tokio::test]
async fn schedule_subarg_repair_record_round_trips_recovery_and_wire() {
    let (mut driver, _tmp) = test_driver(8);
    let original = serde_json::json!({
        "action": "loop.start",
        "args": { "interval": 30, "limit": "1", "prompt": "p" }
    });
    let dispatch = driver
        .dispatch_schedule_action_repaired(&original)
        .await
        .expect("repairable call must dispatch");
    // Mirror the TurnOutcome::ScheduleAction recording (outer recovery is
    // Clean here, so the sub-arg repair is the recorded recovery).
    driver
        .record_schedule_tool_call(ScheduleToolCallRecord {
            agent: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::default(),
            call_id: "call-jobs-repair".to_string(),
            original_input_json: original.clone(),
            wire_input_json: dispatch.wire_args.clone(),
            recovery: dispatch.recovery,
            hard_fail: false,
            output: dispatch.output,
            duration_ms: 1,
        })
        .await;

    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.call_id == "call-jobs-repair")
        .unwrap();
    // original_input keeps the model's stringified `limit`.
    assert_eq!(
        row.original_input_json["args"]["limit"],
        serde_json::json!("1")
    );
    // wire_input carries the coerced integer.
    assert_eq!(row.wire_input_json["args"]["limit"], serde_json::json!(1));
    // recovery_kind/recovery_stage round-trip the shape repair.
    assert!(matches!(
        row.recovery,
        crate::db::tool_calls::Recovery::ShapeRepair {
            stage: "parse_stringified_number",
            ..
        }
    ));
}

#[tokio::test]
async fn dispatch_timer_is_loop_with_limit_one() {
    let (mut driver, _tmp) = test_driver(8);
    let out = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 5, "prompt": "fire", "limit": 1 }
        }))
        .await
        .unwrap();
    assert!(out.starts_with("started timer"), "got {out}");
}

#[tokio::test]
async fn dispatch_list_and_capacity_error() {
    let (mut driver, _tmp) = test_driver(1);
    let empty: serde_json::Value = serde_json::from_str(
        &driver
            .dispatch_schedule_action(&serde_json::json!({ "action": "list" }))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(empty["scheduled"].as_array().unwrap().len(), 0);
    assert_eq!(empty["swarm"]["running"], 0);
    assert_eq!(empty["swarm"]["queued"], 0);
    driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "p", "limit": 2 }
        }))
        .await
        .unwrap();
    let listed: serde_json::Value = serde_json::from_str(
        &driver
            .dispatch_schedule_action(&serde_json::json!({ "action": "list" }))
            .await
            .unwrap(),
    )
    .unwrap();
    let scheduled = listed["scheduled"].as_array().unwrap();
    assert_eq!(scheduled.len(), 1, "got {listed}");
    assert_eq!(scheduled[0]["kind"], "loop");
    assert_eq!(scheduled[0]["status"], "pending");
    assert_eq!(scheduled[0]["executions_completed"], 0);
    assert_eq!(scheduled[0]["execution_limit"], serde_json::json!(2));
    assert!(
        scheduled[0]["job_id"]
            .as_str()
            .unwrap()
            .starts_with("sched-")
    );
    assert_eq!(scheduled[0]["label"], "p");
    // Cap is 1 — a second start errors.
    let err = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "q", "limit": 2 }
        }))
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("max concurrent scheduled tasks"));
}

#[tokio::test]
async fn schedule_tool_call_record_persists_wire_and_original() {
    let (driver, _tmp) = test_driver(8);
    let original = serde_json::json!({ "action": "list" });
    let wire = serde_json::json!({ "action": "list", "args": {} });
    driver
        .record_schedule_tool_call(ScheduleToolCallRecord {
            agent: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::default(),
            call_id: "call-sched-1".to_string(),
            original_input_json: original.clone(),
            wire_input_json: wire.clone(),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            output: "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}".to_string(),
            duration_ms: 3,
        })
        .await;

    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .await
        .unwrap();
    let row = rows.iter().find(|r| r.tool == "schedule").unwrap();
    assert_eq!(row.call_id, "call-sched-1");
    assert_eq!(row.original_input_json, original);
    assert_eq!(row.wire_input_json, wire);
    assert!(!row.hard_fail);
    assert_eq!(
        row.output,
        "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}"
    );
}

/// §5 dispatch record (implementation note): a dispatched
/// `schedule` action also lands a `tool_call` row on the export timeline
/// (`session_events`), not just the `tool_call_events` stats table — so the
/// export reflects the successful native call, not only failed detours.
#[tokio::test]
async fn schedule_dispatch_emits_tool_call_session_event() {
    let (driver, _tmp) = test_driver(8);
    driver
        .record_schedule_tool_call(ScheduleToolCallRecord {
            agent: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::default(),
            call_id: "call-sched-evt".to_string(),
            original_input_json: serde_json::json!({ "action": "list" }),
            wire_input_json: serde_json::json!({ "action": "list", "args": {} }),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            output: "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}".to_string(),
            duration_ms: 3,
        })
        .await;

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let tool_call = events
        .iter()
        .find(|e| e.kind == "tool_call" && e.call_id.as_deref() == Some("call-sched-evt"))
        .expect("schedule dispatch should emit a tool_call session event");
    assert_eq!(tool_call.data["tool"], "schedule");
    assert_eq!(tool_call.data["hard_fail"], false);
    assert_eq!(tool_call.data["original_input"]["action"], "list");
}

#[tokio::test]
async fn dispatch_background_tail_unknown_id() {
    let (mut driver, _tmp) = test_driver(8);
    let out = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "background.tail",
            "args": { "job_id": "sched-nope" }
        }))
        .await
        .unwrap();
    assert!(out.contains("no live background"), "got {out}");
}

/// `finish_delegation_shrink`: a COLD-at-return parent (no-cache
/// provider → always cold) with a computed prune-shrink resumes on the
/// SHRUNK context — the driver swaps the foreground frame's history.
#[tokio::test]
async fn finish_delegation_shrink_cold_swaps_parent_history() {
    use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
    use crate::engine::deleg_shrink::DelegationShrink;

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Parent (foreground) frame carries elidable duplicate reads.
    driver.stack[0].history = dup_read_history();
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "parent has something prunable"
    );

    // A tracker on a no-cache provider is always cold; pre-compute the
    // prune-shrink as the parallel task would have.
    let none = CacheConfig {
        mode: CacheMode::None,
        ttl_secs: 300,
    };
    let mut tracker = DelegationShrink::new(none, &ShrinkConfig::default());
    let shrunk = crate::engine::deleg_shrink::prune_shrink(&driver.stack[0].history);
    tracker.set_shrunk(shrunk);

    driver.finish_delegation_shrink(tracker, None, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // Cold → resumed on the shrunk context: the foreground history is
    // now fully pruned (nothing left elidable).
    assert!(
        prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "cold parent resumed on the shrunk (pruned) context"
    );
}

/// `finish_delegation_shrink`: a HOT-at-return parent (cache-capable,
/// within TTL) keeps its FULL context even when a shrink was computed —
/// no quality loss, the cache is paid for.
#[tokio::test]
async fn finish_delegation_shrink_hot_keeps_full() {
    use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
    use crate::engine::deleg_shrink::DelegationShrink;

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver.stack[0].history = dup_read_history();

    // Ephemeral cache, generous TTL, tracker started "now" → hot.
    let ephemeral = CacheConfig {
        mode: CacheMode::Ephemeral,
        ttl_secs: 3600,
    };
    let mut tracker = DelegationShrink::new(ephemeral, &ShrinkConfig::default());
    tracker.set_shrunk(vec![Message::user("shrunk")]);

    driver.finish_delegation_shrink(tracker, None, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // Hot → full context retained: still has the elidable duplicate.
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "hot parent kept its full (un-shrunk) context"
    );
}

/// `begin_delegation_shrink` on a no-cache provider spawns an EAGER
/// shrink task that finishes promptly (ZERO delay); the prune-shrink
/// result is adopted on `finish`. Exercises the full begin→finish path.
#[tokio::test]
async fn begin_delegation_shrink_eager_on_no_cache() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Default test driver uses provider `lmstudio` with no cache config
    // → CacheMode::None → eager.
    driver.stack[0].history = dup_read_history();
    let parent_full = driver.stack[0].history.clone();
    let (tracker, handle) = driver.begin_delegation_shrink(parent_full);
    assert!(handle.is_some(), "a shrink task was spawned");

    // Let the eager task run to completion.
    let handle = handle.unwrap();
    let shrunk = handle.await.unwrap();
    assert!(
        prune::dedup_plan(&shrunk).is_empty(),
        "eager prune-shrink produced a pruned history"
    );

    // Re-run begin to get a fresh tracker + handle to finish with the
    // already-computed result (the prior handle was consumed above).
    let (mut tracker2, h) = driver.begin_delegation_shrink(driver.stack[0].history.clone());
    if let Some(h) = h {
        h.abort();
    }
    tracker2.set_shrunk(shrunk);
    let _ = tracker; // first tracker not needed further
    driver.finish_delegation_shrink(tracker2, None, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // No-cache provider is always cold → swapped to the shrunk context.
    assert!(prune::dedup_plan(&driver.stack[0].history).is_empty());
}

#[tokio::test]
async fn resolve_child_cwd_accepts_relative_dot_and_absolute_inside_workspace() {
    let (driver, tmp) = test_driver(8);
    let child_dir = tmp.path().join("child");
    std::fs::create_dir(&child_dir).unwrap();

    let relative = driver.resolve_child_cwd(Some("child")).unwrap();
    assert_eq!(relative.requested.as_deref(), Some("child"));
    assert_eq!(relative.resolved, child_dir.canonicalize().unwrap());

    let dot = driver.resolve_child_cwd(Some(".")).unwrap();
    assert_eq!(dot.requested.as_deref(), Some("."));
    assert_eq!(dot.resolved, tmp.path().canonicalize().unwrap());

    let absolute = driver
        .resolve_child_cwd(Some(child_dir.to_str().unwrap()))
        .unwrap();
    assert_eq!(absolute.resolved, child_dir.canonicalize().unwrap());
}

#[tokio::test]
async fn resolve_child_cwd_rejects_missing_files_and_outside_workspace() {
    let (driver, tmp) = test_driver(8);
    let file = tmp.path().join("not-a-dir.txt");
    std::fs::write(&file, "x").unwrap();

    let missing = driver.resolve_child_cwd(Some("missing")).unwrap_err();
    assert!(missing.contains("does not exist or is not a directory"));

    let file_err = driver
        .resolve_child_cwd(Some(file.to_str().unwrap()))
        .unwrap_err();
    assert!(file_err.contains("does not exist or is not a directory"));

    let outside = tempfile::tempdir().unwrap();
    let outside_err = driver
        .resolve_child_cwd(Some(outside.path().to_str().unwrap()))
        .unwrap_err();
    assert!(outside_err.contains("outside trusted workspace"));
}

/// A follow-up persists under the SAME handle (passed as `existing`), so
/// the caller can keep re-querying with one stable handle.
#[tokio::test]
async fn persist_reuses_existing_handle_on_followup() {
    let (driver, tmp) = test_driver(8);
    let h1 = driver
        .persist_subagent_handle("explore", &[Message::user("q1")], Some(tmp.path()), None)
        .unwrap();
    let h2 = driver
        .persist_subagent_handle(
            "explore",
            &[Message::user("q1"), Message::user("q2")],
            Some(tmp.path()),
            Some(&h1),
        )
        .unwrap();
    assert_eq!(h1, h2, "a follow-up keeps the same handle");
    // The transcript was refreshed (upsert) to the longer history.
    let got = driver
        .rehydrate_handle(&h2, "explore", Some(tmp.path()), true)
        .unwrap();
    assert_eq!(got.len(), 2);
}

/// A finished `builder` (write-capable, interactive by default) can be
/// persisted under a handle and re-queried via it — the round trip returns
/// the same transcript, so the follow-up resumes with prior context. The
/// re-query path is agent-name-agnostic: `builder` rehydrates exactly like
/// `explore`.
#[tokio::test]
async fn builder_followup_persist_and_rehydrate_round_trip() {
    let (driver, tmp) = test_driver(8);
    let history = vec![
        Message::user("implement the flag"),
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
        Message::assistant("done"),
    ];
    let handle = driver
        .persist_subagent_handle("builder", &history, Some(tmp.path()), None)
        .expect("a builder handle is minted");
    // Stored under the `builder` agent name; re-querying as `builder` rehydrates.
    let got = driver
        .rehydrate_handle(&handle, "builder", Some(tmp.path()), true)
        .expect("builder rehydrates");
    assert_eq!(got.len(), history.len());
    // Re-querying that handle under a DIFFERENT agent name is stale (the
    // handle belongs to `builder`).
    assert!(
        driver
            .rehydrate_handle(&handle, "explore", Some(tmp.path()), true)
            .is_err()
    );
}

/// A `builder` follow-up persisting more work under the SAME handle upserts
/// the transcript (idempotent handle lifecycle), same as `explore`.
#[tokio::test]
async fn builder_followup_refreshes_handle_idempotently() {
    let (driver, tmp) = test_driver(8);
    let h1 = driver
        .persist_subagent_handle(
            "builder",
            &[Message::user("step 1")],
            Some(tmp.path()),
            None,
        )
        .unwrap();
    let h2 = driver
        .persist_subagent_handle(
            "builder",
            &[Message::user("step 1"), Message::assistant("did step 1")],
            Some(tmp.path()),
            Some(&h1),
        )
        .unwrap();
    assert_eq!(h1, h2);
    assert_eq!(
        driver
            .rehydrate_handle(&h2, "builder", Some(tmp.path()), true)
            .unwrap()
            .len(),
        2
    );
}

/// The `docs` pipeline is excluded from follow-up: it never persists a
/// handle, so any `docs` resume is stale (told to spawn fresh).
#[tokio::test]
async fn docs_is_excluded_from_followup() {
    assert!(!crate::engine::builtin::is_followup_eligible("docs"));
    assert!(!crate::engine::builtin::is_followup_eligible(
        "docs-resolver"
    ));
    assert!(!crate::engine::builtin::is_followup_eligible(
        "docs-answerer"
    ));
    // builder/explore/custom are all eligible.
    assert!(crate::engine::builtin::is_followup_eligible("builder"));
    assert!(crate::engine::builtin::is_followup_eligible("explore"));
    assert!(crate::engine::builtin::is_followup_eligible(
        "my-custom-subagent"
    ));
}

/// End-to-end lock composition for a write-capable follow-up: the finished
/// `builder`'s locks are snapshotted on suspend; a follow-up re-acquires them
/// HASH-MATCHED when the worktree is unchanged, and the §3c write guard
/// holds (the reawakened builder may write the still-matching file).
#[tokio::test]
async fn write_capable_followup_reacquires_locks_hash_matched() {
    let (driver, tmp) = test_driver(8);
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "v1").unwrap();
    let sid = driver.session.id;
    // Original builder run: acquire + write, then finish (suspend snapshots).
    driver.locks.acquire(&p, "builder", sid).unwrap();
    driver
        .locks
        .check_write_permitted(&p, "builder", sid)
        .unwrap();
    driver.locks.suspend_agent("builder", sid).unwrap();
    assert!(
        driver.locks.holder(&p).is_none(),
        "finish releases the lock"
    );
    // Follow-up: worktree unchanged → resume reacquires hash-matched.
    let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
    assert_eq!(reacquired.len(), 1);
    assert_eq!(
        driver.locks.holder(&p).map(|(_, a)| a).as_deref(),
        Some("builder")
    );
    // The reawakened builder may write the still-matching file (§3c holds).
    driver
        .locks
        .check_write_permitted(&p, "builder", sid)
        .unwrap();
}

/// No stale write when the worktree changed under a reawakened builder: a
/// drifted file is NOT reacquired and its §3c read record is dropped, so a
/// write is refused until the builder re-reads (`readlock`) it.
#[tokio::test]
async fn write_capable_followup_forces_reread_on_drift() {
    let (driver, tmp) = test_driver(8);
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "v1").unwrap();
    let sid = driver.session.id;
    driver.locks.acquire(&p, "builder", sid).unwrap();
    driver.locks.suspend_agent("builder", sid).unwrap();
    // The user / another agent edits the file while the builder was finished.
    std::fs::write(&p, "v2-drift").unwrap();
    let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
    assert!(reacquired.is_empty(), "drifted file must not reacquire");
    assert!(driver.locks.holder(&p).is_none());
    // Write is refused (the read record was invalidated) — no stale write.
    assert!(
        driver
            .locks
            .check_write_permitted(&p, "builder", sid)
            .is_err()
    );
    // After an explicit re-read the write is permitted again.
    driver.locks.note_read(&p, "builder", sid);
    driver
        .locks
        .check_write_permitted(&p, "builder", sid)
        .unwrap();
}

/// Lock re-acquire failure because another writer now holds the path is
/// surfaced (the builder simply doesn't hold it) and the follow-up does NOT
/// force-write — single-writer is preserved, the other writer keeps the
/// lock.
#[tokio::test]
async fn write_capable_followup_defers_to_other_lock_holder() {
    let (driver, tmp) = test_driver(8);
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "v1").unwrap();
    let sid = driver.session.id;
    // A second session/agent grabs the path while the builder is finished.
    let other = driver
        .session
        .db
        .create_session("p", "/x", "builder")
        .await
        .unwrap();
    driver.locks.acquire(&p, "builder", sid).unwrap();
    driver.locks.suspend_agent("builder", sid).unwrap();
    driver
        .locks
        .acquire(&p, "builder", other.session_id)
        .unwrap();
    // Follow-up resume can't reacquire — the other holder wins.
    let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
    assert!(reacquired.is_empty());
    assert_eq!(
        driver.locks.holder(&p).map(|(s, _)| s),
        Some(other.session_id)
    );
    // The reawakened builder cannot write the path (no force-write).
    assert!(
        driver
            .locks
            .check_write_permitted(&p, "builder", sid)
            .is_err()
    );
}

/// The cache-aware reuse decision is driven by the session's active cache
/// config + time-since-last-send. The test driver's provider declares no
/// cache, so a follow-up takes the no-cache-reuse path deterministically.
#[tokio::test]
async fn followup_reuse_decision_no_cache_provider() {
    let (driver, _t) = test_driver(8);
    assert_eq!(
        driver.followup_reuse_decision(),
        crate::engine::prune::FollowupReuse::NoCacheReuse
    );
}
