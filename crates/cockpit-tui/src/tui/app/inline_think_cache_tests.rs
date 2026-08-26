use super::{App, new_pending};
use cockpit_client::presentation::AssistantAttemptId;
use cockpit_core::engine::TurnEvent;
use std::cell::Cell;
use std::fs;

fn configured_app(tmp: &tempfile::TempDir) -> App {
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    fs::write(cockpit.join("config.json"), "{}").unwrap();
    let provider_dir = cockpit.join("providers");
    fs::create_dir(&provider_dir).unwrap();
    fs::write(
        provider_dir.join("p.json"),
        r#"{"url":"https://example.test","models":[{"id":"m"}]}"#,
    )
    .unwrap();
    App::new(Some(tmp.path()), false)
}

#[test]
fn pending_strip_value_resolves_once_per_pending_turn() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let calls = Cell::new(0);

    let first = app.pending_or_insert_with_strip("agent".to_string(), |_| {
        calls.set(calls.get() + 1);
        true
    });
    assert!(first.strip_think);

    let second = app.pending_or_insert_with_strip("agent".to_string(), |_| {
        calls.set(calls.get() + 1);
        false
    });
    assert!(second.strip_think);
    assert_eq!(calls.get(), 1);

    app.pending = None;
    let next = app.pending_or_insert_with_strip("agent".to_string(), |_| {
        calls.set(calls.get() + 1);
        false
    });
    assert!(!next.strip_think);
    assert_eq!(calls.get(), 2);
}

#[test]
fn raw_assistant_text_delta_does_not_drive_live_provisional_or_think_parse() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.pending = Some(new_pending("agent".to_string(), true));

    app.apply_event(TurnEvent::AssistantTextDelta {
        agent: "agent".to_string(),
        delta: "<think>hidden</think>answer".to_string(),
    });

    let pending = app.pending.as_ref().expect("pending retained");
    assert!(
        pending.text.is_empty(),
        "raw live deltas must not update provisional body"
    );
    assert!(pending.reasoning.is_empty());
}

#[test]
fn typed_display_delta_before_thinking_started_initializes_provisional() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let attempt = AssistantAttemptId::new(3);

    app.apply_event(TurnEvent::AssistantDisplayReasoningDelta {
        agent: "agent".to_string(),
        attempt_id: attempt,
        delta: "reasoning".to_string(),
    });

    let pending = app.pending.as_ref().expect("pending initialized");
    assert_eq!(pending.name, "agent");
    assert_eq!(pending.reasoning, "reasoning");
    assert_eq!(pending.attempt_id, Some(attempt));
    assert!(!pending.strip_think);
}

#[test]
fn typed_display_attempt_correlation_rejects_stale_after_reset() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let failed = AssistantAttemptId::new(1);
    let replacement = AssistantAttemptId::new(2);

    app.apply_event(TurnEvent::ThinkingStarted {
        agent: "agent".to_string(),
        turn_id: Some("t1".to_string()),
    });
    app.apply_event(TurnEvent::AssistantDisplayTextDelta {
        agent: "agent".to_string(),
        attempt_id: failed,
        delta: "partial".to_string(),
    });
    app.apply_event(TurnEvent::AssistantDisplayAttemptReset {
        agent: "agent".to_string(),
        failed_attempt_id: failed,
        replacement_attempt_id: replacement,
        reason: "timeout".to_string(),
    });
    assert!(app.pending.is_none());
    assert_eq!(app.active_display_attempt_id, Some(replacement));

    app.apply_event(TurnEvent::AssistantDisplayTextDelta {
        agent: "agent".to_string(),
        attempt_id: failed,
        delta: "late".to_string(),
    });
    assert!(
        app.pending.is_none(),
        "late failed-attempt delta must not recreate provisional"
    );

    app.apply_event(TurnEvent::AssistantDisplayTextDelta {
        agent: "agent".to_string(),
        attempt_id: replacement,
        delta: "ok".to_string(),
    });
    assert_eq!(app.pending.as_ref().map(|p| p.text.as_str()), Some("ok"));

    // Complete for the failed attempt must not finalize a wrong row.
    app.apply_event(TurnEvent::AssistantDisplayComplete {
        agent: "agent".to_string(),
        attempt_id: failed,
        assistant: cockpit_client::presentation::AssistantTextPayload {
            text: "wrong".to_string(),
            presentation_text: None,
            reasoning: String::new(),
            seq: Some(1),
            response_performance: None,
        },
    });
    assert_eq!(
        app.pending.as_ref().map(|p| p.text.as_str()),
        Some("ok"),
        "stale Complete must not overwrite active attempt"
    );
}
