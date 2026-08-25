use std::fs;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{App, Overlay};
use cockpit_core::engine::TurnEvent;
use cockpit_core::engine::model::InferenceErrorClass;
use cockpit_proto::AuthFailureKind;

fn write_provider(root: &std::path::Path, template: Option<&str>, url: &str) {
    let cockpit = root.join(".cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    fs::write(&config_path, "{}").unwrap();
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
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
        error_class: InferenceErrorClass::Http(403),
        detail: "credentials rejected".into(),
        auth_failure: Some(kind),
    }
}

fn write_auth_header(root: &std::path::Path, value: &str) {
    let config_path = root.join(".cockpit/config.json");
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
    let provider = serde_json::json!({
        "url": "https://example.test/v1",
        "headers": [{"name": "Authorization", "value": value}],
        "models": [{"id": "m"}],
    });
    fs::write(provider_path, serde_json::to_vec(&provider).unwrap()).unwrap();
}

fn app_for_provider(root: &std::path::Path) -> App {
    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(root),
        || App::new(Some(root), false),
    )
}

/// Trust `root` in the promoted daemon. The redacted provider snapshot fetched
/// when opening the auth-failure recovery surface is trust-gated on the daemon
/// side (DB-owned), so the local `with_workspace_trust_policy` override is not
/// enough — the daemon reads its own store. The transient runtime only carries
/// the request; the promoted daemon context persists across the reducers'
/// per-call runtimes.
fn seed_daemon_workspace_trust(root: &std::path::Path) {
    use cockpit_proto::{Request, Response, WorkspaceTrustMode};
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("auth-recovery trust seed runtime");
    runtime.block_on(async {
        let client = crate::tui::settings::settings_daemon_client()
            .await
            .expect("settings daemon client for trust seed");
        let project_root = root.display().to_string();
        let expected_config_generation = match client
            .request(Request::GetWorkspaceTrust {
                project_root: project_root.clone(),
            })
            .await
            .expect("trust read transport")
            .expect("trust read response")
        {
            Response::WorkspaceTrust {
                config_generation, ..
            } => config_generation,
            other => panic!("unexpected trust read: {other:?}"),
        };
        match client
            .request(Request::SetWorkspaceTrust {
                project_root,
                mode: WorkspaceTrustMode::Trust,
                expected_config_generation,
            })
            .await
            .expect("trust set transport")
            .expect("trust set response")
        {
            Response::WorkspaceTrustSet { .. } => {}
            other => panic!("unexpected trust set: {other:?}"),
        }
    });
}

#[test]
fn auth_failure_notice_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    // Opening the provider edit surface fetches the daemon's redacted provider
    // snapshot; promote an isolated in-process daemon so that RPC resolves
    // in-memory instead of timing out on a real socket.
    let _daemon = cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();
    write_provider(tmp.path(), None, "https://example.test/v1");
    seed_daemon_workspace_trust(tmp.path());
    let mut app = app_for_provider(tmp.path());
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

    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(tmp.path()),
        || app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::ALT)),
    );
    assert_eq!(app.dialog.test_provider_surface(), Some("edit"));
}

#[test]
fn annotation_cleared_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_provider(tmp.path(), None, "https://example.test/v1");
    let mut app = app_for_provider(tmp.path());
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
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_provider(tmp.path(), None, "https://example.test/v1");
    let mut app = app_for_provider(tmp.path());

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

/// Auth-failure clearing keys off the daemon's *redacted* provider view
/// (`tui-config-single-source`): the TUI never sees credential values, so the
/// fingerprint tracks provider auth *structure* (url, header names, whether a
/// credential is configured). A structural change, once the refreshed snapshot
/// lands, clears the stale annotation. (A pure secret-value edit is no longer
/// client-observable — the daemon owns credential resolution.)
#[test]
fn annotation_cleared_on_provider_auth_structure_change() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_provider(tmp.path(), None, "https://example.test/v1");
    write_auth_header(tmp.path(), "Bearer old-secret");
    let mut app = app_for_provider(tmp.path());
    app.apply_event(auth_event(AuthFailureKind::CredentialsRejected {
        status: 401,
    }));
    assert_eq!(app.auth_failure_annotations.len(), 1);

    // Structural change: a new provider URL. Visible in the redacted view.
    let config_path = tmp.path().join(".cockpit/config.json");
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
    fs::write(
        provider_path,
        serde_json::to_vec(&serde_json::json!({
            "url": "https://example.test/v2",
            "headers": [{"name": "Authorization", "value": "Bearer old-secret"}],
            "models": [{"id": "m"}],
        }))
        .unwrap(),
    )
    .unwrap();
    // Detached: the bootstrap snapshot refresh stands in for the daemon push.
    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(tmp.path()),
        || app.refresh_bootstrap_config_snapshot(),
    );
    app.clear_changed_provider_auth_failures();

    assert!(app.auth_failure_annotations.is_empty());
}

#[test]
fn oauth_expired_notice_deep_links() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    // Opening the OAuth provider surface fetches the daemon's redacted provider
    // snapshot; promote an isolated in-process daemon so that RPC resolves
    // in-memory instead of timing out on a real socket.
    let _daemon = cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();
    write_provider(
        tmp.path(),
        Some("codex"),
        "https://chatgpt.com/backend-api/codex",
    );
    seed_daemon_workspace_trust(tmp.path());
    let mut app = app_for_provider(tmp.path());
    app.apply_event(auth_event(AuthFailureKind::OAuthExpired {
        provider: "p".into(),
    }));

    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(tmp.path()),
        || app.open_auth_failure_provider(),
    );

    assert_eq!(app.dialog.test_provider_surface(), Some("oauth"));
}

#[test]
fn auth_failure_annotations_start_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let app = App::new(Some(tmp.path()), false);
    assert!(app.auth_failure_annotations.is_empty());
    assert!(app.auth_failure_notice.is_none());
}
