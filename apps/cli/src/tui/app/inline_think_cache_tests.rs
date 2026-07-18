use super::{App, new_pending};
use crate::engine::TurnEvent;
use std::cell::Cell;
use std::fs;

fn configured_app(tmp: &tempfile::TempDir) -> App {
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
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
fn assistant_text_delta_uses_cached_pending_strip_value() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.pending = Some(new_pending("agent".to_string(), false));

    app.apply_event(TurnEvent::AssistantTextDelta {
        agent: "agent".to_string(),
        delta: "<think>body when disabled</think>answer".to_string(),
    });

    let pending = app.pending.as_ref().expect("pending retained");
    assert_eq!(pending.text, "<think>body when disabled</think>answer");
    assert!(pending.reasoning.is_empty());
}

#[test]
fn delta_before_thinking_started_initializes_cached_pending_turn() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.apply_event(TurnEvent::ReasoningDelta {
        agent: "agent".to_string(),
        delta: "reasoning".to_string(),
    });

    let pending = app.pending.as_ref().expect("pending initialized");
    assert_eq!(pending.name, "agent");
    assert_eq!(pending.reasoning, "reasoning");
}
