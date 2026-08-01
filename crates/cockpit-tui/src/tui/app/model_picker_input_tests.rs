use super::{App, HistoryEntry, Overlay};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use std::fs;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn ctrl_press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn snapshot_picker(app: &App) -> crate::tui::model_picker::ModelPickerDialog {
    let mut cfg = cockpit_config::providers::ProvidersConfig::default();
    cfg.providers.insert(
        "p".to_string(),
        cockpit_config::providers::ProviderEntry {
            models: vec![cockpit_config::providers::ModelEntry {
                id: "a".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    crate::tui::model_picker::ModelPickerDialog::open_with_failures(
        cfg,
        app.launch.active_model.clone(),
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .expect("model picker opens from snapshot")
}

fn write_config(path: &std::path::Path) {
    fs::write(path, r#"{"providers":{"p":{}}}"#).unwrap();
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(path, "p").unwrap();
    fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    fs::write(
        provider_path,
        r#"{"url":"https://example.test","models":[{"id":"a"}]}"#,
    )
    .unwrap();
}

#[test]
fn model_picker_selection_closes_without_local_config_write() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.overlay = Overlay::ModelPicker(snapshot_picker(&app));
    let history_len = app.history.len();
    let usage_len = app.pending_usage.len();

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert!(matches!(app.overlay, Overlay::ModelPicker(_)));
    assert!(app.history.len() > history_len);
    assert_eq!(app.pending_usage.len(), usage_len + 1);
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    let active = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers()
        .active_model;
    assert_eq!(active, None);
}

#[test]
fn model_picker_session_and_default_writes_config() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join("config").join("cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    let mut picker = crate::tui::model_picker::ModelPickerDialog::open_with_failures(
        cockpit_config::providers::ConfigDoc::load(&config_path)
            .unwrap()
            .providers(),
        None,
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    assert!(picker.handle_key(ctrl_press(KeyCode::Enter)));
    app.overlay = Overlay::ModelPicker(picker);
    app.close_model_picker(true);
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a and make default")),
        "history: {:?}",
        app.history.last()
    );
    let active = cockpit_config::providers::ConfigDoc::providers_from_paths(
        &cockpit_config::dirs::config_file_paths_for_load(tmp.path()),
    )
    .active_model;
    assert_eq!(active, None);
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a and make default"))
    );
}

#[test]
fn model_picker_default_write_failure_still_applies_session() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let source = tempfile::tempdir().unwrap();
    let source_config = source.path().join("config.json");
    write_config(&source_config);
    _env.set_cockpit_config(&tmp.path().join("missing.json"));
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    let mut picker = crate::tui::model_picker::ModelPickerDialog::open_with_failures(
        cockpit_config::providers::ConfigDoc::load(&source_config)
            .unwrap()
            .providers(),
        None,
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    assert!(picker.handle_key(ctrl_press(KeyCode::Enter)));
    app.overlay = Overlay::ModelPicker(picker);
    app.close_model_picker(true);
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a and make default"))
    );
}

#[test]
fn chrome_active_model_unchanged_on_rejected_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.launch.active_model = Some(("old-provider".to_string(), "old-model".to_string()));
    app.overlay = Overlay::ModelPicker(snapshot_picker(&app));

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert_eq!(
        app.launch.active_model,
        Some(("old-provider".to_string(), "old-model".to_string()))
    );
    let active = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers()
        .active_model;
    assert_eq!(active, None);
}

#[test]
fn model_picker_selection_records_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.overlay = Overlay::ModelPicker(snapshot_picker(&app));

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert!(
        matches!(app.overlay, Overlay::ModelPicker(_)),
        "picker recovery with error {:?}",
        match &app.overlay {
            Overlay::ModelPicker(picker) => picker.error_text(),
            _ => None,
        }
    );
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a")),
        "expected model summary line, got {:?}",
        app.history.last()
    );
    let active = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers()
        .active_model;
    assert_eq!(active, None);
}

#[test]
fn chrome_renders_session_derived_active_model() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    write_config(&cockpit.join("config.json"));

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.apply_event(cockpit_core::engine::TurnEvent::ActiveModelState {
        provider: "p".to_string(),
        model: "a".to_string(),
        config_provider: Some("other".to_string()),
        config_model: Some("old".to_string()),
        diverged: true,
        generation: 2,
    });

    assert_eq!(
        app.launch.active_model,
        Some(("p".to_string(), "a".to_string()))
    );
    assert!(app.launch.active_model_diverged);

    app.apply_event(cockpit_core::engine::TurnEvent::ActiveModelState {
        provider: "stale".to_string(),
        model: "stale".to_string(),
        config_provider: None,
        config_model: None,
        diverged: false,
        generation: 1,
    });

    assert_eq!(
        app.launch.active_model,
        Some(("p".to_string(), "a".to_string()))
    );
    assert!(app.launch.active_model_diverged);
}

#[test]
fn config_drift_state_retains_config_model_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    write_config(&cockpit.join("config.json"));

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.apply_event(cockpit_core::engine::TurnEvent::ActiveModelState {
        provider: "session-p".to_string(),
        model: "session-m".to_string(),
        config_provider: Some("config-p".to_string()),
        config_model: Some("config-m".to_string()),
        diverged: true,
        generation: 2,
    });

    let drift = app.config_drift.as_ref().expect("drift state retained");
    assert_eq!(drift.config_label(), "config-p/config-m");
    assert_eq!(app.session_model_label(), "session-p/session-m");
}

#[test]
fn config_drift_stale_generation_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    write_config(&cockpit.join("config.json"));

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.apply_event(cockpit_core::engine::TurnEvent::ActiveModelState {
        provider: "p".to_string(),
        model: "a".to_string(),
        config_provider: Some("p".to_string()),
        config_model: Some("a".to_string()),
        diverged: false,
        generation: 3,
    });
    app.apply_event(cockpit_core::engine::TurnEvent::ActiveModelState {
        provider: "stale-p".to_string(),
        model: "stale-m".to_string(),
        config_provider: Some("config-p".to_string()),
        config_model: Some("config-m".to_string()),
        diverged: true,
        generation: 2,
    });

    assert!(!app.launch.active_model_diverged);
    assert_eq!(
        app.launch.active_model,
        Some(("p".to_string(), "a".to_string()))
    );
    assert!(app.config_drift.is_none());
}
