use super::*;
use cockpit_config::dirs::test_support::IsolatedCockpitHome;
use cockpit_config::providers::{ConfigDoc, ModelEntry, ProviderEntry, ProvidersConfig};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn daemon_paths(tmp: &tempfile::TempDir) -> cockpit_core::daemon::DaemonPaths {
    cockpit_core::daemon::DaemonPaths {
        pid_file: tmp.path().join("daemon.pid"),
        socket: tmp.path().join("daemon.sock"),
        ephemeral: false,
    }
}

fn write_config(cwd: &std::path::Path, cfg: &ProvidersConfig) {
    let cockpit = cwd.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    let mut doc = ConfigDoc::load(&cockpit.join("config.json")).unwrap();
    doc.write(cfg).unwrap();
}

fn write_raw_config(cwd: &std::path::Path, json: &str) {
    let cockpit = cwd.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(cockpit.join("config.json"), json).unwrap();
}

fn config_with_provider(provider_id: &str, model_id: &str) -> ProvidersConfig {
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        url: "http://localhost:1/v1".to_string(),
        ..Default::default()
    };
    provider.models.push(ModelEntry {
        id: model_id.to_string(),
        ..Default::default()
    });
    cfg.providers.insert(provider_id.to_string(), provider);
    cfg
}

#[test]
fn daemon_autostart_ask_shows_modal() {
    let tmp = tempfile::tempdir().unwrap();
    let state = daemon_not_running_state_with_spawn(
        cockpit_core::daemon::DaemonStatus::NotRunning,
        daemon_paths(&tmp),
        cockpit_config::extended::DaemonAutostart::Ask,
        None,
        false,
        || panic!("ask mode must not spawn"),
    );

    assert!(state.prompt.is_some());
    assert!(!state.connected);
    assert!(!state.daemonless);
}

#[test]
fn daemon_autostart_failure_falls_back_to_modal() {
    let tmp = tempfile::tempdir().unwrap();
    let state = daemon_not_running_state_with_spawn(
        cockpit_core::daemon::DaemonStatus::NotRunning,
        daemon_paths(&tmp),
        cockpit_config::extended::DaemonAutostart::Shared,
        None,
        false,
        || anyhow::bail!("boom"),
    );

    assert!(state.prompt.is_some());
    assert!(!state.connected);
    assert!(state.notice.is_none());
}

#[test]
fn daemon_autostart_notice_shows_once() {
    let tmp = tempfile::tempdir().unwrap();
    let db = cockpit_db::Db::open_in_memory().unwrap();
    let first = daemon_not_running_state_with_spawn(
        cockpit_core::daemon::DaemonStatus::NotRunning,
        daemon_paths(&tmp),
        cockpit_config::extended::DaemonAutostart::Private,
        Some(&db),
        db.app_flag_seen(DAEMON_AUTOSTART_NOTICE_FLAG).unwrap(),
        || panic!("private mode must not spawn"),
    );
    let second = daemon_not_running_state_with_spawn(
        cockpit_core::daemon::DaemonStatus::NotRunning,
        daemon_paths(&tmp),
        cockpit_config::extended::DaemonAutostart::Private,
        Some(&db),
        db.app_flag_seen(DAEMON_AUTOSTART_NOTICE_FLAG).unwrap(),
        || panic!("private mode must not spawn"),
    );

    assert!(first.notice.is_some());
    assert!(second.notice.is_none());
}

#[test]
fn first_run_chains_provider_then_model() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = IsolatedCockpitHome::new(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::open_providers_add(tmp.path());
    write_config(tmp.path(), &config_with_provider("p", "m"));
    app.dialog.test_mark_provider_add_done("p");

    assert!(app.service_first_run_flow());

    assert_eq!(
        app.dialog.test_page_name(),
        Some(cockpit_core::wizard::MODEL_WIZARD_ID)
    );
    assert_eq!(
        app.dialog.test_setup_prefill(),
        Some(cockpit_core::wizard::WizardAnswer::Select("p".to_string()))
    );
    app.dialog
        .handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(
        app.dialog.test_setup_answer("provider"),
        Some(cockpit_core::wizard::WizardAnswer::Select("p".to_string()))
    );
    assert_eq!(
        app.dialog.test_setup_prefill(),
        Some(cockpit_core::wizard::WizardAnswer::Select(
            "p:m".to_string()
        ))
    );
}

#[test]
fn no_model_send_opens_wizard_preserves_input() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = IsolatedCockpitHome::new(tmp.path());
    write_config(tmp.path(), &ProvidersConfig::default());
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.composer.set("draft message".to_string());

    assert!(!app.submit_input());

    assert_eq!(app.composer.text(), "draft message");
    assert!(app.queue.is_empty());
    assert!(app.history.is_empty());
    assert!(app.dialog.test_provider_is_add());
}

#[test]
fn trust_dialog_persists_decision() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = IsolatedCockpitHome::new(tmp.path());
    write_raw_config(tmp.path(), r#"{"daemon":{"autostart":"ask"}}"#);
    let db = cockpit_db::Db::open_in_memory().unwrap();
    let root = cockpit_config::trust::resolve_trust_root(tmp.path()).unwrap();
    let mut app = App::new_with_db_and_workspace_trust(
        Some(tmp.path()),
        false,
        db.clone(),
        StartupWorkspaceTrust::Pending(root.clone()),
    );

    assert_eq!(app.dialog.test_page_name(), Some("workspace_trust"));
    assert!(!app.apply_workspace_trust_choice(
        root.clone(),
        cockpit_db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
    ));

    let decision = db
        .workspace_trust_by_root(&root.root)
        .unwrap()
        .expect("trust decision persisted");
    assert_eq!(
        decision.mode,
        cockpit_db::workspace_trust::WorkspaceTrustMode::IgnoreConfig
    );
    cockpit_config::trust::clear_runtime_policy_for_tests();
}
