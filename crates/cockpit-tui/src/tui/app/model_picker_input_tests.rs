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

fn write_config(path: &std::path::Path) {
    fs::write(path, "{}").unwrap();
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
    app.overlay = Overlay::ModelPicker(
        crate::tui::model_picker::ModelPickerDialog::open(tmp.path(), &app.usage_models)
            .expect("model picker opens from valid config"),
    );
    let history_len = app.history.len();
    let usage_len = app.pending_usage.len();

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert!(!matches!(app.overlay, Overlay::ModelPicker(_)));
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
    app.overlay = Overlay::ModelPicker(
        crate::tui::model_picker::ModelPickerDialog::open(tmp.path(), &app.usage_models)
            .expect("model picker opens from valid config"),
    );

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
    app.overlay = Overlay::ModelPicker(
        crate::tui::model_picker::ModelPickerDialog::open(tmp.path(), &app.usage_models)
            .expect("model picker opens from valid config"),
    );

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert!(
        !matches!(app.overlay, Overlay::ModelPicker(_)),
        "picker stayed open with error {:?}",
        match &app.overlay {
            Overlay::ModelPicker(picker) => picker.error_text(),
            _ => None,
        }
    );
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("model")),
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
