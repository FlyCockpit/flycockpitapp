use std::fs;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{App, Overlay};
use crate::daemon::proto::AuthFailureKind;
use crate::engine::TurnEvent;

fn write_provider(root: &std::path::Path, template: Option<&str>, url: &str) {
    let cockpit = root.join(".cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    fs::write(&config_path, "{}").unwrap();
    let provider_path =
        crate::config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
    fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    let mut provider = serde_json::json!({
        "url": url,
        "models": [{"id": "m"}],
    });
    if let Some(template) = template {
        provider["template"] = serde_json::json!(template);
    }
    fs::write(provider_path, serde_json::to_vec(&provider).unwrap()).unwrap();
}

fn auth_event(kind: AuthFailureKind) -> TurnEvent {
    TurnEvent::InferenceFailed {
        agent: "subagent".into(),
        provider: "p".into(),
        model: "m".into(),
        error_class: "http_403".into(),
        detail: "credentials rejected".into(),
        auth_failure: Some(kind),
    }
}

fn write_auth_header(root: &std::path::Path, value: &str) {
    let config_path = root.join(".cockpit/config.json");
    let provider_path =
        crate::config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
    let provider = serde_json::json!({
        "url": "https://example.test/v1",
        "headers": [{"name": "Authorization", "value": value}],
        "models": [{"id": "m"}],
    });
    fs::write(provider_path, serde_json::to_vec(&provider).unwrap()).unwrap();
}

#[test]
fn auth_failure_notice_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    write_provider(tmp.path(), None, "https://example.test/v1");
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.apply_event(auth_event(AuthFailureKind::CredentialsRejected {
        status: 403,
    }));

    let notice = app.persistent_notice_text().expect("auth notice");
    assert!(notice.contains("[switch model]"), "{notice}");
    assert!(notice.contains("[fix provider]"), "{notice}");

    app.handle_key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::ALT));
    assert!(matches!(app.overlay, Overlay::ModelPicker(_)));
    app.overlay = Overlay::None;

    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::ALT));
    assert_eq!(app.dialog.test_provider_surface(), Some("edit"));
}

#[test]
fn annotation_cleared_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    write_provider(tmp.path(), None, "https://example.test/v1");
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_event(auth_event(AuthFailureKind::CredentialsRejected {
        status: 401,
    }));
    assert_eq!(app.auth_failure_annotations.len(), 1);

    app.apply_event(TurnEvent::InferenceSucceeded {
        provider: "p".into(),
        model: "m".into(),
    });

    assert!(app.auth_failure_annotations.is_empty());
}

#[test]
fn nested_subagent_auth_recovery_updates_when_pane_is_not_active() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    write_provider(tmp.path(), None, "https://example.test/v1");
    let mut app = App::new(Some(tmp.path()), false);

    app.apply_event(TurnEvent::NestedTurn {
        task_call_id: "task-1".into(),
        label: "researcher".into(),
        parent_task_call_id: None,
        inner: Box::new(auth_event(AuthFailureKind::CredentialsRejected {
            status: 401,
        })),
    });
    assert_eq!(app.auth_failure_annotations.len(), 1);
    assert_eq!(app.auth_failure_notice.as_ref().unwrap().model, "m");

    app.apply_event(TurnEvent::NestedTurn {
        task_call_id: "task-1".into(),
        label: "researcher".into(),
        parent_task_call_id: None,
        inner: Box::new(TurnEvent::InferenceSucceeded {
            provider: "p".into(),
            model: "m".into(),
        }),
    });
    assert!(app.auth_failure_annotations.is_empty());
    assert!(app.auth_failure_notice.is_none());
}

#[test]
fn annotation_cleared_on_credential_change() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    write_provider(tmp.path(), None, "https://example.test/v1");
    write_auth_header(tmp.path(), "Bearer old-secret");
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_event(auth_event(AuthFailureKind::CredentialsRejected {
        status: 401,
    }));

    write_auth_header(tmp.path(), "Bearer new-secret");
    app.clear_changed_provider_auth_failures();

    assert!(app.auth_failure_annotations.is_empty());
}

#[test]
fn oauth_expired_notice_deep_links() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    write_provider(
        tmp.path(),
        Some("codex"),
        "https://chatgpt.com/backend-api/codex",
    );
    let mut app = App::new(Some(tmp.path()), false);
    app.apply_event(auth_event(AuthFailureKind::OAuthExpired {
        provider: "p".into(),
    }));

    app.open_auth_failure_provider();

    assert_eq!(app.dialog.test_provider_surface(), Some("oauth"));
}

#[test]
fn auth_failure_annotations_start_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let app = App::new(Some(tmp.path()), false);
    assert!(app.auth_failure_annotations.is_empty());
    assert!(app.auth_failure_notice.is_none());
}
