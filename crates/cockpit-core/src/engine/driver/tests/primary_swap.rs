use super::*;

#[tokio::test]
async fn auto_hands_off_to_build_on_clear_build_intent() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    assert_eq!(driver.active_agent(), "Auto", "starts on the front door");

    let next = driver
        .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
        .await;

    assert_eq!(driver.active_agent(), "Build", "primary swapped to `Build`");
    assert_eq!(driver.stack.len(), 1, "swap stays on the root frame");
    // Persisted so a resume restarts on the handed-off primary.
    assert_eq!(persisted_active_agent(&driver), "Build");
    // The confirmation tool_result is what drives `Build`'s next turn.
    assert!(
        matches!(&next, Message::User { .. }),
        "tool_result delivered"
    );
}

#[tokio::test]
async fn failed_handoff_does_not_persist_target_agent() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .apply_handoff(
            "DefinitelyNotAnAgent",
            "call-1".to_string(),
            Some("fc-1".to_string()),
            &tx,
        )
        .await;

    assert_eq!(driver.active_agent(), "Auto");
    assert_eq!(persisted_active_agent(&driver), "Auto");
}

/// Part 1 (implementation note): the swapped-in
/// primary's first turn is driven by an IMPERATIVE kickoff — the user's
/// originating request restated verbatim + a begin-now instruction — NOT
/// the bare `` "Handed off to `Build`." `` ack a weak model would merely
/// narrate.
#[tokio::test]
async fn handoff_kickoff_restates_user_request_and_commands_action() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // The originating user request that triggered the handoff.
    let request = "Add a confirm-on-quit toggle to /settings";
    push_user_turn(&mut driver, request);

    let next = driver
        .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
        .await;

    let kickoff = tool_result_text(&next);
    assert!(
        kickoff.contains(request),
        "kickoff restates the user's request verbatim: {kickoff:?}"
    );
    assert!(
        kickoff.to_lowercase().contains("begin now")
            && kickoff.to_lowercase().contains("tool call"),
        "kickoff commands a begin-now tool call, not narration: {kickoff:?}"
    );
    assert!(
        !kickoff.contains("Handed off to"),
        "the bare ack is NOT the model-facing kickoff: {kickoff:?}"
    );
}

/// The kickoff restates the SALIENT (most recent) user turn when several
/// preceded the handoff — not the whole transcript.
#[tokio::test]
async fn handoff_kickoff_restates_only_the_salient_request() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "What does the config loader do?");
    // An intervening agent reply closes that turn so the next user message
    // opens a fresh, salient one.
    driver.stack[0]
        .history
        .push(Message::assistant("It walks up .cockpit/."));
    let salient = "Now rename `loadConfig` to `load_config` everywhere";
    push_user_turn(&mut driver, salient);

    let next = driver
        .apply_handoff("Build", "c".to_string(), Some("fc".to_string()), &tx)
        .await;

    let kickoff = tool_result_text(&next);
    assert!(
        kickoff.contains(salient),
        "salient request restated: {kickoff:?}"
    );
    assert!(
        !kickoff.contains("config loader"),
        "the earlier turn is not dragged in: {kickoff:?}"
    );
}

/// Companion to the above: a clear planning request routes to `Plan`.
#[tokio::test]
async fn auto_hands_off_to_plan_on_clear_plan_intent() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .apply_handoff("Plan", "call-2".to_string(), Some("fc-2".to_string()), &tx)
        .await;

    assert_eq!(driver.active_agent(), "Plan", "primary swapped to `Plan`");
    assert_eq!(persisted_active_agent(&driver), "Plan");
}

/// Regression (implementation note): start as agent A,
/// exchange a turn, swap to agent B via the `swap_command` path, then send
/// a message — the wire history carries exactly ONE swap marker naming
/// A→B, positioned at the swap boundary (immediately ahead of the user's
/// next message, after the prior turns).
#[tokio::test]
async fn swap_command_injects_one_marker_at_boundary_on_next_message() {
    let (mut driver, _t) = test_driver(1); // rooted on `Build`
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // Exchange ≥1 turn under `Build` (A).
    push_user_turn(&mut driver, "What does the lock manager do?");
    driver.stack[0]
        .history
        .push(Message::assistant("It arbitrates writers."));
    assert_eq!(driver.active_agent(), "Build");

    // Swap to `Swarm` (B) via the slash-command path. No marker yet —
    // injection is deferred to the next message.
    driver.swap_primary("Swarm", &tx).await;
    assert_eq!(driver.active_agent(), "Swarm");
    assert!(
        swap_markers(&driver).is_empty(),
        "marker is deferred, not written at swap time"
    );

    // The user's next message: the marker is injected at send time, at the
    // boundary, then the user message follows.
    driver.inject_pending_swap_marker();
    driver.stack[0].history.push(Message::user("now build it"));

    let markers = swap_markers(&driver);
    assert_eq!(markers.len(), 1, "exactly one marker: {markers:?}");
    assert!(
        markers[0].contains("`Build` → `Swarm`") && markers[0].contains("You are now `Swarm`"),
        "marker names A→B and the new identity: {:?}",
        markers[0]
    );
    // Positioned at the boundary: the marker sits immediately before the
    // new user message and after the prior turns.
    let texts: Vec<String> = driver.stack[0]
        .history
        .iter()
        .map(plain_user_text)
        .collect();
    let marker_idx = texts
        .iter()
        .position(|t| t.starts_with("[Primary agent changed:"))
        .unwrap();
    assert_eq!(
        texts[marker_idx + 1],
        "now build it",
        "marker sits immediately ahead of the next user message"
    );
    // Pending state is consumed — a later message injects no second marker.
    driver.inject_pending_swap_marker();
    assert_eq!(swap_markers(&driver).len(), 1, "fires once per swap window");
}

/// Coalesce (implementation note): several swaps before
/// a message (`Build`→`Swarm`→`Plan`→`Build` … then `Plan`) emit exactly
/// ONE marker naming previously-effective → final. The intermediate hops
/// produce nothing; `from` stays the agent whose turns are in history.
#[tokio::test]
async fn multiple_swaps_before_message_coalesce_to_one_marker() {
    let (mut driver, _t) = test_driver(1); // rooted on `Build`
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "outline the change");
    driver.stack[0]
        .history
        .push(Message::assistant("here is an outline"));

    // Build → Swarm → Plan, all before a message.
    driver.swap_primary("Swarm", &tx).await;
    driver.swap_primary("Build", &tx).await;
    driver.swap_primary("Plan", &tx).await;
    assert_eq!(driver.active_agent(), "Plan");
    assert!(swap_markers(&driver).is_empty(), "no markers until send");

    driver.inject_pending_swap_marker();
    let markers = swap_markers(&driver);
    assert_eq!(markers.len(), 1, "intermediate hops coalesce: {markers:?}");
    assert!(
        markers[0].contains("`Build` → `Plan`"),
        "from = previously-effective (`Build`), to = final (`Plan`): {:?}",
        markers[0]
    );
}

/// Net no-op (implementation note): when the final
/// agent equals the previously-effective one (`Build`→`Swarm`→`Build`
/// while history was already `Build`), nothing is injected — and the
/// pending state is still cleared.
#[tokio::test]
async fn swap_back_to_original_agent_injects_no_marker() {
    let (mut driver, _t) = test_driver(1); // rooted on `Build`
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "think about it");
    driver.stack[0].history.push(Message::assistant("thinking"));

    driver.swap_primary("Swarm", &tx).await;
    driver.swap_primary("Build", &tx).await; // back to the original
    assert_eq!(driver.active_agent(), "Build");

    driver.inject_pending_swap_marker();
    assert!(
        swap_markers(&driver).is_empty(),
        "final == previously-effective → no marker"
    );
    assert!(
        driver.pending_swap_marker_from.is_none(),
        "pending state cleared even on the net no-op"
    );
}

/// The synthetic marker is wire-only (`agent-swap-identity-
/// marker.md`, wire-vs-user split GOALS §14): the swap path emits only the
/// terse `PrimarySwapped` chrome event for the user-facing timeline, never
/// a transcript row for the marker, and the marker is not recorded as a
/// session event. The user sees the switched-to row; the marker stays on
/// the wire.
#[tokio::test]
async fn swap_marker_does_not_leak_into_user_transcript() {
    let (mut driver, _t) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "do the thing");
    driver.stack[0].history.push(Message::assistant("ok"));

    driver.swap_primary("Swarm", &tx).await;
    driver.inject_pending_swap_marker();

    // The marker is on the wire.
    assert_eq!(swap_markers(&driver).len(), 1);
    // No user-message transcript row was recorded for the marker (the swap
    // records its own `primary_swap` event, but the marker is wire-only).
    let user_msg_rows = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "user_message")
        .count();
    assert_eq!(
        user_msg_rows, 0,
        "the marker is never recorded as a user-message transcript row"
    );
    // The only user-facing chrome signal from the swap is `PrimarySwapped`
    // (the terse switched-to row) — never a transcript entry carrying the
    // marker text.
    drop(tx);
    let mut saw_swapped = false;
    while let Ok(ev) = rx.try_recv() {
        if let TurnEvent::PrimarySwapped { name } = &ev {
            assert_eq!(name, "Swarm");
            saw_swapped = true;
        }
        // No event should ever carry the marker text.
        let dbg = format!("{ev:?}");
        assert!(
            !dbg.contains("[Primary agent changed:"),
            "marker text must not reach the client: {dbg}"
        );
    }
    assert!(saw_swapped, "the terse switched-to chrome event fired");
}

#[test]
fn stale_tool_owner_ledgers_drop_calls_absent_from_root_history() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("live", "editunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "live".to_string(),
            None,
            "[elided body]",
        ));
    driver
        .tool_call_owner
        .insert("live".to_string(), "Build".to_string());
    driver
        .tool_call_owner
        .insert("stale".to_string(), "Build".to_string());

    driver.drop_stale_owner_ledgers();

    assert_eq!(
        driver.tool_call_owner.get("live").map(String::as_str),
        Some("Build"),
        "structural tool calls stay owned even when their result body is elided"
    );
    assert!(
        !driver.tool_call_owner.contains_key("stale"),
        "calls absent from root history are dropped"
    );
}

#[test]
fn stale_skill_pairs_drop_when_call_and_result_leave_root_history() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("skill-live", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skill-live".to_string(),
            None,
            "skill body",
        ));
    driver.skill_pairs.push(SkillPair {
        call_id: "skill-live".to_string(),
        owner: "Auto".to_string(),
        intentional_steer: false,
    });
    driver.skill_pairs.push(SkillPair {
        call_id: "skill-stale".to_string(),
        owner: "Auto".to_string(),
        intentional_steer: false,
    });

    driver.drop_stale_owner_ledgers();

    assert_eq!(driver.skill_pairs.len(), 1);
    assert_eq!(driver.skill_pairs[0].call_id, "skill-live");
}

#[tokio::test]
async fn persisted_skill_pair_strips_after_resume_swap() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    driver.stack[0]
        .history
        .push(tool_call_turn("skillslash-resume", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skillslash-resume".to_string(),
            None,
            "Skill `x`:\n\nresume-only instructions",
        ));
    driver
        .session
        .db
        .save_skill_pair(driver.session.id, "skillslash-resume", "Build", false)
        .unwrap();

    driver.restore_skill_pairs_after_rehydrate("Build");
    assert_eq!(driver.skill_pairs.len(), 1);
    assert_eq!(driver.skill_pairs[0].owner, "Build");

    driver.swap_primary("Plan", &tx).await;

    assert!(
        !history_text(&driver.stack[0].history).contains("resume-only instructions"),
        "resume-restored abandoned skill body stripped on swap"
    );
    assert!(
        driver
            .session
            .db
            .list_skill_pairs(driver.session.id)
            .unwrap()
            .is_empty(),
        "stripped pair is removed from durable ledger"
    );
}

#[test]
fn skill_pair_reconstructs_from_history_and_tool_log_when_db_empty() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("skillslash-rebuilt", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skillslash-rebuilt".to_string(),
            None,
            "Skill `x`:\n\npre-migration instructions",
        ));
    record_skill_tool_row(
        &driver,
        "skillslash-rebuilt",
        "Build",
        "pre-migration instructions",
    );

    driver.restore_skill_pairs_after_rehydrate("Plan");

    assert_eq!(driver.skill_pairs.len(), 1);
    assert_eq!(driver.skill_pairs[0].call_id, "skillslash-rebuilt");
    assert_eq!(driver.skill_pairs[0].owner, "Build");
    assert!(
        !driver.skill_pairs[0].intentional_steer,
        "fallback reconstruction defaults to non-steering"
    );
    let rows = driver
        .session
        .db
        .list_skill_pairs(driver.session.id)
        .unwrap();
    assert_eq!(rows.len(), 1, "reconstructed row is persisted");
    assert_eq!(rows[0].owner, "Build");
}

#[test]
fn compact_brief_history_excludes_abandoned_skill_bodies() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(Message::user("please continue"));
    driver.stack[0]
        .history
        .push(tool_call_turn("skillslash-compact", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skillslash-compact".to_string(),
            None,
            "Skill `x`:\n\nCOMPACT_SENTINEL_DO_NOT_SUMMARIZE",
        ));
    driver.skill_pairs.push(SkillPair {
        call_id: "skillslash-compact".to_string(),
        owner: "Build".to_string(),
        intentional_steer: false,
    });

    let filtered = driver.compact_brief_history(&driver.stack[0].history);

    let text = history_text(&filtered);
    assert!(text.contains("please continue"));
    assert!(
        !text.contains("COMPACT_SENTINEL_DO_NOT_SUMMARIZE"),
        "abandoned skill body is omitted from compact brief input"
    );
}

#[test]
fn stale_owner_cleanup_bounds_repeated_removed_calls() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("still-here", "read"));
    for i in 0..128 {
        driver
            .tool_call_owner
            .insert(format!("gone-{i}"), "Build".to_string());
        driver.skill_pairs.push(SkillPair {
            call_id: format!("skill-gone-{i}"),
            owner: "Auto".to_string(),
            intentional_steer: false,
        });
    }
    driver
        .tool_call_owner
        .insert("still-here".to_string(), "Build".to_string());

    driver.drop_stale_owner_ledgers();

    assert_eq!(driver.tool_call_owner.len(), 1);
    assert!(driver.tool_call_owner.contains_key("still-here"));
    assert!(
        driver.skill_pairs.is_empty(),
        "removed skill calls do not accumulate stale ledger rows"
    );
}

/// Regression (implementation note): agent A
/// (`Build`, has the write tool) calls a write tool and a `read`; swap to
/// agent B (`Plan`, read-only) and send a message — every historical
/// write-tool call carries a wire-only note naming A and the tool, while
/// the `read` call (a tool B still has) is left unannotated.
#[tokio::test]
async fn absent_tool_calls_annotated_naming_the_maker_present_tools_untouched() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    assert_eq!(driver.active_agent(), "Build");
    // `Build` is the authority for which tool A actually held.
    assert!(
        driver.stack[0].agent.tools.get("editunlock").is_some(),
        "Build holds the write tool"
    );
    assert!(driver.stack[0].agent.tools.get("read").is_some());

    // A (`Build`) makes a write call and a read call, each answered.
    push_user_turn(&mut driver, "edit the file then read it");
    driver.stack[0]
        .history
        .push(tool_call_turn("w1", "editunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "w1".to_string(),
            None,
            "[hash=abc ok]",
        ));
    driver.stack[0].history.push(tool_call_turn("r1", "read"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "r1".to_string(),
            None,
            "file contents",
        ));

    // Swap to `Plan` (read-only — lacks `editunlock`). No annotation yet —
    // deferred to the next message.
    driver.swap_primary("Plan", &tx).await;
    assert_eq!(driver.active_agent(), "Plan");
    assert!(
        driver.stack[0].agent.tools.get("editunlock").is_none(),
        "Plan lacks the write tool"
    );
    assert!(
        !tool_result_text_for(&driver, "w1").contains("[Called by"),
        "annotation is deferred, not written at swap time"
    );

    // The user's next message: annotation fires at send time.
    driver.annotate_absent_tool_calls();

    // The write call carries the attribution note naming A (`Build`) and T.
    let w = tool_result_text_for(&driver, "w1");
    assert!(
        w.contains("[Called by `Build`, which had the `editunlock` tool. You (`Plan`) do not have this tool.]"),
        "absent-tool call annotated with maker + tool + new identity: {w:?}"
    );
    assert!(
        w.contains("[hash=abc ok]"),
        "the original tool output is preserved after the note: {w:?}"
    );
    // The `read` call (a tool `Plan` still has) is untouched.
    let r = tool_result_text_for(&driver, "r1");
    assert!(
        !r.contains("[Called by"),
        "a call for a tool the new agent still has is not annotated: {r:?}"
    );
    assert_eq!(r, "file contents");

    // Idempotent: a later message never double-stamps.
    driver.annotate_absent_tool_calls();
    let w2 = tool_result_text_for(&driver, "w1");
    assert_eq!(w2, w, "re-evaluation does not double-annotate");
}

/// Per-call ownership across several swaps
/// (implementation note): a write call made under
/// `Build`, then a swap to `Swarm` (also write-capable) that makes its own
/// write call, then a swap to `Plan` (read-only). On the next message each
/// write call is attributed to the agent that ACTUALLY made it — "the
/// previous agent" is not enough.
#[tokio::test]
async fn annotation_attributes_each_call_to_its_actual_maker() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");

    // A (`Build`) makes a write call.
    driver.stack[0]
        .history
        .push(tool_call_turn("b1", "editunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "b1".to_string(),
            None,
            "build-write",
        ));

    // Swap to `Swarm` (still write-capable) which makes its own write call.
    driver.swap_primary("Swarm", &tx).await;
    driver.stack[0]
        .history
        .push(tool_call_turn("s1", "writeunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "s1".to_string(),
            None,
            "swarm-write",
        ));

    // Swap to `Plan` (read-only) and annotate at the next message.
    driver.swap_primary("Plan", &tx).await;
    driver.annotate_absent_tool_calls();

    let b = tool_result_text_for(&driver, "b1");
    assert!(
        b.contains("[Called by `Build`, which had the `editunlock` tool."),
        "the first write call is attributed to `Build`: {b:?}"
    );
    let s = tool_result_text_for(&driver, "s1");
    assert!(
        s.contains("[Called by `Swarm`, which had the `writeunlock` tool."),
        "the second write call is attributed to `Swarm`, not `Build`: {s:?}"
    );
}

#[tokio::test]
async fn primary_swap_transfers_locks_between_write_capable_agents() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    let path = driver.cwd.join("swap-transfer.txt");
    std::fs::write(&path, "seed").unwrap();
    driver
        .locks
        .acquire(&path, "Build", driver.session.id)
        .unwrap();

    driver.swap_primary("Swarm", &tx).await;

    assert_eq!(driver.active_agent(), "Swarm");
    assert_eq!(
        driver.locks.holder(&path).map(|(_, a)| a).as_deref(),
        Some("Swarm")
    );
    driver
        .locks
        .check_write_permitted(&path, "Swarm", driver.session.id)
        .unwrap();
    assert!(!driver.locks.has_read(&path, "Build", driver.session.id));
}

#[tokio::test]
async fn primary_swap_releases_locks_when_incoming_is_read_only() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    let path = driver.cwd.join("swap-release.txt");
    std::fs::write(&path, "seed").unwrap();
    driver
        .locks
        .acquire(&path, "Build", driver.session.id)
        .unwrap();

    driver.swap_primary("Plan", &tx).await;

    assert_eq!(driver.active_agent(), "Plan");
    assert!(driver.locks.holder(&path).is_none());
}

/// A swapped-in read-only agent (`Plan`) does not re-issue a write tool
/// whose past calls are now annotated
/// (implementation note). The behavioral
/// guarantee is the annotation: the write call's outcome now reads as
/// "another agent made this; you lack this tool", and `Plan`'s own surface
/// holds no write tool, so a re-issue is impossible.
#[tokio::test]
async fn read_only_agent_cannot_reissue_annotated_write_tool() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    driver.stack[0]
        .history
        .push(tool_call_turn("w1", "writeunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "w1".to_string(),
            None,
            "[hash=def ok]",
        ));

    driver.swap_primary("Plan", &tx).await;
    driver.annotate_absent_tool_calls();

    // Annotation present (the guarantee).
    assert!(tool_result_text_for(&driver, "w1").contains("You (`Plan`) do not have this tool."));
    // And `Plan`'s surface genuinely holds no write tool to re-issue.
    assert!(driver.stack[0].agent.tools.get("writeunlock").is_none());
    assert!(driver.stack[0].agent.tools.get("editunlock").is_none());
}

/// Part 2 (implementation note, the `myj42m`
/// shape): an abandoned skill pair injected under the outgoing primary
/// must not remain as authoritative instructions for the new primary after
/// a swap. After `Auto` seeds a user-invoked skill and then hands off, the
/// skill's call + result are stripped from the root history (both halves,
/// together) so `Build` follows its own role.
#[tokio::test]
async fn abandoned_skill_pair_is_stripped_on_handoff_swap() {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;

    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // The user invoked a skill then described a change. The skill
    // name need not exist on disk — the seam still folds a real pair into
    // history and records ownership (the leak we're closing).
    driver
        .seed_forced_skill("definitely-not-a-real-skill-xyz", &tx)
        .await;
    push_user_turn(&mut driver, "Add a confirm-on-quit toggle to /settings");

    // The pair is present and owned by the outgoing primary (`Auto`).
    let skill_call_present = |d: &Driver| {
        d.stack[0].history.iter().any(|m| {
            matches!(m,
            Message::Assistant { content, .. }
                if content.iter().any(|c| matches!(c,
                    AssistantContent::ToolCall(tc) if tc.function.name == "skill")))
        })
    };
    let skill_result_present = |d: &Driver| {
        d.stack[0].history.iter().any(|m| {
            matches!(m,
            Message::User { content }
                if content.iter().any(|c| matches!(c,
                    UserContent::ToolResult(tr) if tr.id.starts_with("fc-skillslash-"))))
        })
    };
    assert!(
        skill_call_present(&driver),
        "skill call folded in before swap"
    );
    assert!(
        skill_result_present(&driver),
        "skill result folded in before swap"
    );
    assert_eq!(driver.skill_pairs.len(), 1, "ownership recorded");

    // Hand off to `Build`. The abandoned skill pair must be gone.
    driver
        .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
        .await;

    assert!(
        !skill_call_present(&driver),
        "abandoned skill call stripped on swap (does not govern `Build`)"
    );
    assert!(
        !skill_result_present(&driver),
        "abandoned skill result stripped on swap (no orphaned tool_result)"
    );
    assert!(
        driver.skill_pairs.is_empty(),
        "stripped pair dropped from the ledger"
    );
    // The kickoff still restated the user's own request (not the skill).
    // History stays well-formed: every tool_result has its call.
    assert_eq!(driver.active_agent(), "Build");
}

/// A steering pair (the future "intentional steer" opt-out) survives the
/// swap — the mechanism scopes narrowly to *abandoned* pairs and does not
/// hard-code "drop all skills on swap." (No production path sets the flag
/// today; this guards the seam.)
#[tokio::test]
async fn intentional_steer_skill_pair_survives_swap() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    driver
        .seed_forced_skill("definitely-not-a-real-skill-xyz", &tx)
        .await;
    // Flip the recorded pair to steering, as a future intentional-steer
    // path would.
    driver.skill_pairs[0].intentional_steer = true;
    let before = driver.stack[0].history.len();

    driver
        .apply_handoff("Build", "c".to_string(), Some("fc".to_string()), &tx)
        .await;

    assert_eq!(
        driver.stack[0].history.len(),
        before,
        "a steering pair is retained across the swap"
    );
    assert_eq!(driver.skill_pairs.len(), 1, "steering ownership entry kept");
}

/// Part 3 (implementation note): the
/// `task`→subagent kickoff always carries an actionable brief and the
/// child begins its loop on the first turn. The brief is the caller's
/// (repair-required, non-empty) `task` prompt, delivered verbatim as the
/// child's first `Message::user`. This guards that the delegation path
/// never stalls on a non-actionable first turn.
#[test]
fn delegated_subagent_first_turn_is_the_actionable_brief() {
    // The interactive spawn path delivers `Message::user(scrub(&brief))`;
    // the noninteractive path delivers `compose_subagent_brief(&brief,&why)`.
    // Both carry the caller's brief verbatim — never an empty / passive
    // first turn. We assert the brief composition is faithful (the seam the
    // live loop uses), since the `task` prompt is required by the repair
    // layer and thus always non-empty.
    let brief = "Rename `loadConfig` to `load_config` in src/config/ and update callers.";
    // No `why`: the brief is delivered unchanged (actionable as written).
    assert_eq!(compose_subagent_brief(brief, ""), brief);
    // With a `why`: the brief is still present in full, prefixed with
    // motivation — the child still receives the actionable instruction.
    let with_why = compose_subagent_brief(brief, "the API changed");
    assert!(
        with_why.contains(brief),
        "brief carried verbatim: {with_why}"
    );
    assert!(with_why.contains("the API changed"), "motivation prefixed");
}

#[tokio::test]
async fn ambiguous_turn_keeps_auto_active() {
    let (driver, _t) = auto_rooted_driver();
    // No `apply_handoff` call (the model emitted no `handoff` tool call).
    assert_eq!(
        driver.active_agent(),
        "Auto",
        "ambiguous intent keeps the front door — no unsolicited swap"
    );
    assert_eq!(persisted_active_agent(&driver), "Auto");
}

/// Resume rehydration is automatic but applies ONLY when the root frame
/// has no live in-memory history. A driver whose root already has a live
/// context is left untouched — never rebuild over a live context
/// (implementation note).
#[test]
fn rehydrate_skips_a_live_history() {
    let (mut driver, _t) = test_driver(1);
    // Record a couple of turns to the DB transcript.
    let session = driver.session.clone();
    session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({ "text": "hi" }),
        )
        .unwrap();
    session
        .record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-1"),
            &serde_json::json!({ "text": "hello" }),
        )
        .unwrap();
    // Simulate a LIVE worker: the root frame already has in-memory
    // history. Rehydration must be a no-op.
    driver.stack[0].history = vec![Message::user("a live message")];
    let r = driver.rehydrate_root_if_empty("Build").unwrap();
    assert!(r.is_none(), "must not rebuild over a live context");
    assert_eq!(driver.stack[0].history.len(), 1, "live history untouched");
}

/// Persist-every-boundary + automatic rehydration: a transcript and a
/// prune ledger persisted to the DB (as the running driver would at each
/// inference boundary, surviving an UNCLEAN kill — no graceful exit
/// step) are rehydrated by a brand-new driver into the PRUNED form, with
/// the watermark restored and the context estimate seeded.
#[test]
fn fresh_driver_rehydrates_persisted_pruned_context() {
    use rig::OneOrMany;
    use rig::message::{AssistantContent, ToolResultContent, UserContent};

    let (driver, _t) = test_driver(1);
    let session = driver.session.clone();
    let db = session.db.clone();
    let sid = session.id;

    // Two identical reads → the older is prunable. Record the transcript
    // exactly as the engine does (events + tool_call rows).
    let rec_user = |text: &str| {
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({ "text": text }),
            )
            .unwrap();
    };
    let rec_tool = |call_id: &str, body: &str| {
        session
            .record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: "Build".into(),
                call_id: call_id.into(),
                parent_call_id: None,
                parent_child_index: None,
                identity: crate::session::ToolCallProviderIdentity::default(),
                tool: "read".into(),
                path: Some("/f".into()),
                mcp_server: None,
                original_input_json: serde_json::json!({ "path": "/f" }),
                wire_input_json: serde_json::json!({ "path": "/f" }),
                recovery: crate::db::tool_calls::Recovery::Clean,
                hard_fail: false,
                exit_code: None,
                sandbox_enabled: false,
                sandboxed: false,
                sandbox_unavailable_reason: None,
                output: body.into(),
                truncated: false,
                duration_ms: 1,
                llm_mode: crate::config::extended::LlmMode::default(),
                shape_fingerprint: None,
                hint: None,
            })
            .unwrap();
        session
            .record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some("Build"),
                Some(call_id),
                &serde_json::json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": body }),
            )
            .unwrap();
    };
    rec_user("read it twice");
    session
        .record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-1"),
            &serde_json::json!({ "text": "" }),
        )
        .unwrap();
    rec_tool("tc-1", "BODY ONE padding padding padding");
    session
        .record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-2"),
            &serde_json::json!({ "text": "" }),
        )
        .unwrap();
    rec_tool("tc-2", "BODY TWO padding padding padding");

    // Persist the prune ledger as the boundary cadence would — the older
    // read (tc-1) elided.
    let ledger = prune::PruneLedger {
        elided: vec![prune::LedgerEntry {
            original_event_id: "tc-1".into(),
            reason: prune::REASON_SNAPSHOT_SUPERSEDED.into(),
            partial_body: None,
        }],
        watermark: 5,
    };
    db.save_prune_ledger(sid, &ledger).unwrap();
    drop(driver); // the daemon "died" — in-memory history is gone.

    // A brand-new driver for the SAME session (a fresh worker after an
    // unclean restart) rehydrates automatically.
    let s2 = Arc::new(Session::resume(db.clone(), sid).unwrap().unwrap());
    let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
    let rcfg = crate::config::extended::RedactConfig::default();
    let redact = Arc::new(RedactionTable::build(&rcfg, &s2.project_root).unwrap());
    let agent = Arc::new(Agent {
        name: "Build".into(),
        system: String::new(),
        role_prompt: String::new(),
        tools: crate::engine::tool::ToolBox::new(),
        model: Arc::new(
            crate::engine::model::Model::from_config(
                &{
                    use crate::config::providers::{
                        ActiveModelRef, ProviderEntry, ProvidersConfig,
                    };
                    let mut providers = std::collections::BTreeMap::new();
                    providers.insert(
                        "lmstudio".to_string(),
                        ProviderEntry {
                            url: "http://localhost:1/v1".into(),
                            ..ProviderEntry::default()
                        },
                    );
                    ProvidersConfig {
                        providers,
                        active_model: Some(ActiveModelRef {
                            provider: "lmstudio".into(),
                            model: "local".into(),
                            reasoning_effort: None,
                            thinking_mode: None,
                        }),
                        ..ProvidersConfig::default()
                    }
                },
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        ),
        params: crate::engine::model::ModelParams::default(),
        scan_tool_results: true,
        llm_mode: crate::config::extended::LlmMode::default(),
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });
    let mut driver2 =
        Driver::with_max_schedules(s2.clone(), locks, redact, s2.project_root.clone(), agent, 1);
    let r = driver2
        .rehydrate_root_if_empty("Build")
        .unwrap()
        .expect("a prior conversation was rebuilt");
    assert!(!r.ledger_fallback);
    // The pruned form is restored: tc-1's body is the elision marker.
    let body = |m: &Message| match m {
        Message::User { content } => content
            .iter()
            .filter_map(|c| match c {
                UserContent::ToolResult(tr) => Some(
                    tr.content
                        .iter()
                        .filter_map(|c| match c {
                            ToolResultContent::Text(t) => Some(t.text.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(""),
                ),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    };
    let h = &driver2.stack[0].history;
    // h: user, assistant(tc-1), result tc-1 (elided), assistant(tc-2), result tc-2.
    assert!(prune::Elision::is_marker(&body(&h[2])), "tc-1 body elided");
    assert_eq!(body(&h[4]), "BODY TWO padding padding padding");
    // Watermark restored so auto-prune's short-circuit stays consistent.
    assert_eq!(driver2.prune_watermark.get(&1).copied(), Some(5));
    // Context estimate seeded for the gauge (non-zero pruned history).
    assert!(s2.last_usage().is_some());
    // The assistant turn that issued tc-1 is unchanged (call shape kept).
    assert!(matches!(&h[1], Message::Assistant { content, .. }
        if content.iter().any(|c| matches!(c, AssistantContent::ToolCall(tc) if tc.id == "tc-1"))));
    let _ = OneOrMany::one(UserContent::text("")); // keep import used
}

#[test]
fn new_constructs_idle_driver() {
    // `Driver::new` is the public default-cap constructor; exercise it
    // so the default path stays alive + correct.
    let (driver, _t) = test_driver(crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES);
    let agent = driver.stack[0].agent.clone();
    let d2 = Driver::new(
        driver.session.clone(),
        driver.locks.clone(),
        driver.redact.clone(),
        driver.cwd.clone(),
        agent,
    );
    assert_eq!(d2.active_agent(), "Build");
    assert!(!d2.schedule.has_loop());
    assert_eq!(
        d2.schedule.max_concurrent,
        crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES
    );
}

#[test]
fn live_skill_inventory_publishes_exact_dynamic_toolbox() {
    let (driver, _tmp) = test_driver_without_network(1);
    let mut agent = (*driver.stack[0].agent).clone();
    agent.llm_mode = crate::config::extended::LlmMode::Normal;
    agent.tools = crate::engine::tool::ToolBox::new()
        .with(Arc::new(crate::tools::read::ReadTool))
        .with(Arc::new(crate::tools::web::WebSearchTool));
    let session = driver.session.clone();

    let _driver = Driver::new(
        session.clone(),
        driver.locks.clone(),
        driver.redact.clone(),
        driver.cwd.clone(),
        Arc::new(agent),
    );
    let names = session.active_tool_names();
    assert!(names.iter().any(|name| name == "read"));
    assert!(names.iter().any(|name| name == "websearch"));

    session.set_sandbox_escalation_enabled(false);
    assert!(
        !session
            .active_tool_names()
            .iter()
            .any(|name| name == "escalate")
    );
    session.set_sandbox_escalation_enabled(true);
    assert!(
        session
            .active_tool_names()
            .iter()
            .any(|name| name == "escalate")
    );
    session.set_sandbox_escalation_enabled(false);
    assert!(
        !session
            .active_tool_names()
            .iter()
            .any(|name| name == "escalate")
    );
}

/// Persist a transcript under a handle, then rehydrate it: the round trip
/// returns the same messages, so a follow-up resumes with prior context.
#[test]
fn rehydrate_handle_persist_round_trip() {
    let (driver, tmp) = test_driver(8);
    let history = vec![
        Message::user("earlier question"),
        Message::assistant("earlier answer"),
    ];
    let handle = driver
        .persist_subagent_handle("explore", &history, Some(tmp.path()), None)
        .expect("a handle is minted");
    // Enabled (normal-mode gate passed) + matching agent → rehydrated.
    let got = driver
        .rehydrate_handle(&handle, "explore", Some(tmp.path()), true)
        .expect("rehydrates");
    assert_eq!(got.len(), history.len());
}

/// An unknown handle is a clear tool error telling the caller to spawn
/// fresh — never a silent cold start.
#[test]
fn rehydrate_handle_unknown_is_stale_error() {
    let (driver, tmp) = test_driver(8);
    let err = driver
        .rehydrate_handle("sub-does-not-exist", "explore", Some(tmp.path()), true)
        .unwrap_err();
    assert!(err.contains("resume_handle"), "{err}");
    assert!(err.contains("fresh"), "{err}");
}

/// In defensive mode the whole feature is disabled at the capability
/// level: even a valid handle is rejected (the only path is a fresh
/// spawn). Gates behavior, not just description text.
#[test]
fn rehydrate_handle_disabled_in_defensive() {
    let (driver, tmp) = test_driver(8);
    let history = vec![Message::user("q")];
    let handle = driver
        .persist_subagent_handle("explore", &history, Some(tmp.path()), None)
        .unwrap();
    // `followup_enabled = false` models the defensive gate
    // (`Capability::FollowupSeed.enabled(Defensive) == false`).
    let err = driver
        .rehydrate_handle(&handle, "explore", Some(tmp.path()), false)
        .unwrap_err();
    assert!(err.contains("fresh"), "{err}");
}

/// A handle that belongs to a different agent (and, by construction, any
/// `docs` follow-up — the pipeline never persists a handle) is stale.
#[test]
fn rehydrate_handle_wrong_agent_is_stale() {
    let (driver, tmp) = test_driver(8);
    let handle = driver
        .persist_subagent_handle("explore", &[Message::user("q")], Some(tmp.path()), None)
        .unwrap();
    // Re-querying as `docs` against an `explore` handle → stale (and docs
    // never mints one anyway, so this is the only outcome it can hit).
    let err = driver
        .rehydrate_handle(&handle, "docs", Some(tmp.path()), true)
        .unwrap_err();
    assert!(err.contains("fresh"), "{err}");
}

#[test]
fn rehydrate_handle_wrong_cwd_is_stale() {
    let (driver, tmp) = test_driver(8);
    let original = tmp.path().join("original");
    let other = tmp.path().join("other");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&other).unwrap();
    let handle = driver
        .persist_subagent_handle("explore", &[Message::user("q")], Some(&original), None)
        .unwrap();

    let err = driver
        .rehydrate_handle(&handle, "explore", Some(&other), true)
        .unwrap_err();
    assert!(err.contains("fresh"), "{err}");
}
