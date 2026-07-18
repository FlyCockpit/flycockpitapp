use super::{App, HistoryEntry, Overlay};
use crate::config::providers::ConfigDoc;
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
    let provider_path = crate::config::providers::provider_file_path_for_config(path, "p").unwrap();
    fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    fs::write(
        provider_path,
        r#"{"url":"https://example.test","models":[{"id":"a"}]}"#,
    )
    .unwrap();
}

#[test]
fn model_picker_save_failure_stays_open_without_success_side_effects() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
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
    fs::write(&config_path, "{not json").unwrap();
    let history_len = app.history.len();
    let usage_len = app.pending_usage.len();

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    let Overlay::ModelPicker(picker) = &app.overlay else {
        panic!("picker remains open");
    };
    assert!(!picker.is_done());
    assert_eq!(app.history.len(), history_len);
    assert_eq!(app.pending_usage.len(), usage_len);
    assert!(!app.usage_models.contains_key("p/a"));
}

#[test]
fn model_picker_save_success_closes_and_records_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
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
    let active = ConfigDoc::load(&config_path)
        .unwrap()
        .providers()
        .active_model
        .expect("active model persisted");
    assert_eq!(active.provider, "p");
    assert_eq!(active.model, "a");
}
