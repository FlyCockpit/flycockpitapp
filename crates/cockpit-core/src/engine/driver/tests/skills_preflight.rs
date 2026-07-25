use super::*;

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
            package_dir: "/skills/firecrawl".to_string(),
            body: "FIRECRAWL BODY".to_string(),
            reason: Some("REASON SHOULD STAY OFF WIRE".to_string()),
        },
        InjectedSkill {
            name: "deploy".to_string(),
            package_dir: "/skills/deploy".to_string(),
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
        wire.contains("Skill `firecrawl` (auto-selected, package directory: /skills/firecrawl):"),
        "each body keeps its auto-selected header"
    );
}

#[test]
fn injected_skill_header_includes_package_directory() {
    use crate::skills::auto_select::InjectedSkill;

    let skills = vec![InjectedSkill {
        name: "review".to_string(),
        package_dir: "/skills/review".to_string(),
        body: "REVIEW BODY".to_string(),
        reason: None,
    }];

    let wire = Driver::fold_injected_skills(&skills, "check this diff");

    assert!(wire.starts_with(
        "Skill `review` (auto-selected, package directory: /skills/review):\n\nREVIEW BODY\n\n---\n\ncheck this diff"
    ));
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

/// A parent resolving an active skill can tag it into the child handoff.
/// An ACTIVE skill contributes its instructions PLUS the
/// delegation framing (we are resolving skill X; it takes precedence over
/// the child's baked-in default), so the child drafts instead of
/// implementing.
#[test]
fn skill_tag_expands_to_instructions() {
    let (mut driver, _tmp) = test_driver(1);
    // The release-notes skill is active in the parent's context (e.g.
    // user-invoked `/release-notes`).
    driver.record_active_skill(
        "release-notes",
        "Turn the rough change summary into release notes. Do NOT implement it.",
    );
    let block = driver.expand_skill_tags("please /skill release-notes now", "builder");
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
    // No spurious not-found note when the requested skill was active.
    assert!(
        !block.contains("not found"),
        "no strip note for an active skill: {block:?}"
    );
}

#[test]
fn delegation_prompt_tags_expand_in_child() {
    let (driver, tmp) = test_driver(1);
    let file = tmp.path().join("handoff.txt");
    std::fs::write(&file, "alpha\nbeta\n").unwrap();

    let expanded = driver.expand_handoff_tags(
        "Read @handoff.txt:1-1",
        tmp.path(),
        crate::config::extended::LlmMode::Normal,
        "builder",
    );

    assert!(expanded.contains("<file path=\"handoff.txt\">"));
    assert!(expanded.contains("alpha"));
}

#[test]
fn subagent_return_tags_reach_caller() {
    let (driver, tmp) = test_driver(1);
    let file = tmp.path().join("report.txt");
    std::fs::write(&file, "finding\nextra\n").unwrap();

    let expanded = driver.expand_handoff_tags(
        "Result uses @report.txt:1-1",
        tmp.path(),
        crate::config::extended::LlmMode::Normal,
        "Build",
    );

    assert!(expanded.contains("<file path=\"report.txt\">"));
    assert!(expanded.contains("finding"));
}

#[test]
fn assembly_blocks_escaping_tag_with_chip() {
    let (driver, tmp) = test_driver(1);
    let child = tmp.path().join("child");
    std::fs::create_dir(&child).unwrap();
    std::fs::write(tmp.path().join("outside.txt"), "secret\n").unwrap();

    let expanded = driver.expand_handoff_tags(
        "Read @../outside.txt:1-1",
        &child,
        crate::config::extended::LlmMode::Normal,
        "builder",
    );

    assert!(expanded.contains("@../outside.txt:1-1"));
    assert!(expanded.contains("[note: @../outside.txt"));
    assert!(expanded.contains("blocked"));
}

/// Host-side validation (validate, don't trust the model): a parent that
/// tags a skill NOT active in its context gets a model-visible note — never a
/// body conjured from thin air, never a hard error.
#[test]
fn skill_tag_unknown_skill_yields_note() {
    let (mut driver, _tmp) = test_driver(1);
    // Only `release-notes` is active; `made-up` is not.
    driver.record_active_skill("release-notes", "release body");
    let block = driver.expand_skill_tags("/skill release-notes and /skill made-up", "builder");
    // The active one is still seeded...
    assert!(
        block.contains("release body"),
        "active skill still seeded: {block:?}"
    );
    // ...and the non-active one is stripped with a model-visible note that
    // names it and explains why.
    assert!(
        block.contains("[note: /skill made-up not found]"),
        "non-active skill stripped with a visible note: {block:?}"
    );
    // The non-active skill's instructions never appear (nothing conjured).
    assert!(
        !block.contains("made-up body"),
        "a non-active skill cannot inject any body: {block:?}"
    );
}

/// Expansion is opt-in: text without a `/skill <name>` tag is unchanged.
#[test]
fn skill_tag_expansion_leaves_untagged_text_unchanged() {
    let (mut driver, _tmp) = test_driver(1);
    driver.record_active_skill("release-notes", "body");
    assert_eq!(
        driver.expand_skill_tags("plain handoff", "builder"),
        "plain handoff"
    );
}

/// End-to-end: a user-invoked `/<skill>` whose body loads makes that skill
/// part of the active set, so a later `/skill <name>` tag can expand it.
/// Writes a real skill under the cwd's seeded scan dir.
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

    // The skill is now active in the parent's context, so tagging it into a
    // child succeeds and carries the loaded body.
    let block = driver.expand_skill_tags("/skill release-notes", "builder");
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
    let block = driver.expand_skill_tags("/skill missing-skill", "builder");
    assert!(
        block.contains("[note: /skill missing-skill not found]"),
        "inactive failed skill should be stripped with a note: {block:?}"
    );
    assert!(
        !block.contains("Skill `missing-skill`:"),
        "failed skill should not inject a seeded skill body: {block:?}"
    );
}
