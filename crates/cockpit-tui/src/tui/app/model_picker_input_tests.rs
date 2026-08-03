use super::{App, HistoryEntry, Overlay};
use crate::tui::agent_runner::AgentRunner;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use std::fs;
use tokio::sync::mpsc;

fn selection(provider: &str, model: &str) -> cockpit_config::providers::ActiveModelRef {
    cockpit_config::providers::ActiveModelRef {
        provider: provider.to_string(),
        model: model.to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    }
}
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

fn snapshot_config() -> cockpit_config::providers::ProvidersConfig {
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
    cfg
}

fn snapshot_picker(app: &App) -> crate::tui::model_picker::ModelPickerDialog {
    crate::tui::model_picker::ModelPickerDialog::open_with_failures(
        snapshot_config(),
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
fn picker_bootstrap_failure_stays_inline_without_false_success() {
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
    assert!(
        matches!(&app.overlay, Overlay::ModelPicker(picker) if picker.error_text().is_some_and(|error| error.contains("could not start a session")))
    );
    assert_eq!(app.history.len(), history_len);
    assert_eq!(app.pending_usage.len(), usage_len + 1);
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    let active = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers()
        .active_model;
    assert_eq!(active, None);
}

#[test]
fn picker_make_default_sends_correlated_request_without_local_write() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join("config").join("cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let picker = crate::tui::model_picker::ModelPickerDialog::open_with_failures(
        cockpit_config::providers::ConfigDoc::load(&config_path)
            .unwrap()
            .providers(),
        None,
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    app.overlay = Overlay::ModelPicker(picker);
    let exit = app.handle_key(ctrl_press(KeyCode::Enter));
    assert!(!exit);
    let request = control_rx
        .try_recv()
        .expect("selection request queued")
        .request;
    assert!(matches!(
        request,
        cockpit_core::daemon::proto::Request::SetActiveModel {
            provider,
            model,
            persist_as_default: true,
            ..
        } if provider == "p" && model == "a"
    ));
    assert!(app.pending_model_selection.is_some());
    assert!(matches!(app.overlay, Overlay::None));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a for this session and saving it as the default")),
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
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a for this session and saving it as the default"))
    );
}

#[test]
fn picker_default_intent_waits_for_daemon_without_local_write() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let source = tempfile::tempdir().unwrap();
    let source_config = source.path().join("config.json");
    write_config(&source_config);
    _env.set_cockpit_config(&tmp.path().join("missing.json"));
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let picker = crate::tui::model_picker::ModelPickerDialog::open_with_failures(
        cockpit_config::providers::ConfigDoc::load(&source_config)
            .unwrap()
            .providers(),
        None,
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    app.overlay = Overlay::ModelPicker(picker);
    let exit = app.handle_key(ctrl_press(KeyCode::Enter));
    assert!(!exit);
    assert!(control_rx.try_recv().is_ok());
    assert!(app.pending_model_selection.is_some());
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a for this session and saving it as the default"))
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
    let (control_tx, _control_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_control_tx(control_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));

    app.launch.active_model = Some(("old-provider".to_string(), "old-model".to_string()));
    app.overlay = Overlay::ModelPicker(snapshot_picker(&app));
    let requested = cockpit_config::providers::ActiveModelRef {
        provider: "p".to_string(),
        model: "a".to_string(),
        reasoning_effort: Some(cockpit_config::providers::ActiveReasoningEffort {
            value: "high".to_string(),
        }),
        thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
        prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
    };
    assert!(app.request_model_selection(
        "/model",
        requested.clone(),
        false,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker,
    ));
    let selection_id = app.pending_model_selection.as_ref().unwrap().selection_id;
    let tag = cockpit_core::daemon::proto::TagExpansionMeta {
        tool: "read".to_string(),
        path: "src/model.rs".to_string(),
        detail: "selected lines".to_string(),
        ok: true,
    };
    app.pending_model_selection
        .as_mut()
        .unwrap()
        .queued_submission = Some(super::QueuedModelSubmission {
        composer_text: "review @src/model.rs".to_string(),
        display: "review @src/model.rs".to_string(),
        submission: cockpit_core::engine::message::UserSubmission {
            text: "review expanded source".to_string(),
            tag_expansions: vec![tag.clone()],
            ..Default::default()
        },
        tag_expansions: vec![tag],
    });
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: "p".to_string(),
        model: "a".to_string(),
        reasoning_effort: Some("high".to_string()),
        thinking_mode: Some("high".to_string()),
        prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Rejected {
            user_message: "provider rejected the selection".to_string(),
            diagnostic_code: "model_switch_rejected".to_string(),
        },
    });
    assert!(matches!(&app.overlay, Overlay::ModelPicker(picker)
            if picker.error_text() == Some("provider rejected the selection")
                && picker.draft_active_model() == Some(&requested)));
    let retry = app
        .retry_model_submission
        .as_ref()
        .expect("rejected selection retains the exact queued submission");
    assert_eq!(retry.composer_text, "review @src/model.rs");
    assert_eq!(retry.submission.text, "review expanded source");
    assert_eq!(retry.tag_expansions[0].path, "src/model.rs");

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
fn reopening_model_picker_expires_stale_request_and_carries_queued_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, _control_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_control_tx(control_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));
    assert!(app.request_model_selection(
        "/model",
        selection("p", "a"),
        false,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker,
    ));
    let pending = app.pending_model_selection.as_mut().unwrap();
    pending.started_at = std::time::Instant::now() - std::time::Duration::from_secs(61);
    pending.queued_submission = Some(super::QueuedModelSubmission {
        composer_text: "held draft".to_string(),
        display: "held draft".to_string(),
        submission: cockpit_core::engine::message::UserSubmission {
            text: "held wire draft".to_string(),
            ..Default::default()
        },
        tag_expansions: Vec::new(),
    });

    app.open_model_picker();

    assert!(app.pending_model_selection.is_none());
    assert_eq!(
        app.retry_model_submission
            .as_ref()
            .map(|queued| queued.submission.text.as_str()),
        Some("held wire draft")
    );
    assert!(matches!(&app.overlay, Overlay::ModelPicker(picker)
        if picker.draft_active_model() == Some(&selection("p", "a"))));
}

#[test]
fn adding_model_from_recovery_picker_preserves_auto_submit_intent() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.submit_after_model_selection = true;
    let picker = crate::tui::model_picker::ModelPickerDialog::open_for_provider_with_failures(
        snapshot_config(),
        "p",
        app.launch.active_model.clone(),
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    app.overlay = Overlay::ModelPicker(picker);

    assert!(!app.handle_key(ctrl_press(KeyCode::Char('a'))));

    assert!(app.submit_after_model_selection);
    assert_eq!(app.reopen_model_picker_after_settings.as_deref(), Some("p"));
    assert!(!matches!(app.dialog, crate::tui::settings::Dialog::None));
}

#[test]
fn quick_model_change_waits_for_terminal_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));

    app.active_model_selection = Some(cockpit_config::providers::ActiveModelRef {
        provider: "old-provider".to_string(),
        model: "old-model".to_string(),
        reasoning_effort: Some(cockpit_config::providers::ActiveReasoningEffort {
            value: "high".to_string(),
        }),
        thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
        prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
    });
    app.apply_quick_commit(crate::tui::quick_dialog::QuickCommit {
        active_model: Some(("p".to_string(), "a".to_string())),
        ..Default::default()
    });

    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("quick model selection is pending")
        .selection_id;
    let request = control_rx.try_recv().expect("quick request");
    match request.request {
        cockpit_core::daemon::proto::Request::SetActiveModel {
            selection_id: actual,
            persist_as_default,
            trigger,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
            ..
        } => {
            assert_eq!(actual, selection_id);
            assert_eq!(reasoning_effort.as_deref(), Some("high"));
            assert_eq!(
                thinking_mode,
                Some(cockpit_config::providers::ThinkingMode::High)
            );
            assert_eq!(
                prompt_cache_retention,
                Some(cockpit_config::providers::PromptCacheRetention::Extended)
            );
            assert!(!persist_as_default);
            assert_eq!(
                trigger,
                cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick
            );
        }
        other => panic!("expected SetActiveModel, got {other:?}"),
    }
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("control request pending");
    app.apply_control_request_outcome(
        request_id,
        cockpit_core::engine::ControlRequestOutcome::Applied,
    );
    assert!(
        !app.history.iter().any(
            |entry| matches!(entry, HistoryEntry::Plain { line } if line.contains("active model is now"))
        ),
        "queue acceptance must not be presented as model-switch success"
    );

    let confirmed = selection("p", "a");
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: confirmed.provider.clone(),
        model: confirmed.model.clone(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: confirmed,
                default_selection: None,
                diverged: true,
                generation: 1,
            },
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
        },
    });

    assert!(app.pending_model_selection.is_none());
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line == "Using p/a for this session.")
    );
}

#[test]
fn quick_model_delivery_rejection_does_not_open_picker() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));

    app.apply_quick_commit(crate::tui::quick_dialog::QuickCommit {
        active_model: Some(("p".to_string(), "a".to_string())),
        ..Default::default()
    });
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("control request pending");
    app.apply_control_request_outcome(
        request_id,
        cockpit_core::engine::ControlRequestOutcome::Rejected("busy".to_string()),
    );

    assert!(app.pending_model_selection.is_none());
    assert!(matches!(app.overlay, Overlay::None));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("/quick: daemon rejected request: busy"))
    );
}

#[test]
fn first_send_waits_for_confirmed_model_then_releases_exact_draft() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers();
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    let (input_tx, mut input_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_channels(control_tx, input_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));
    app.composer.set("send this exact draft".to_string());

    assert!(!app.submit_input());
    assert!(matches!(app.overlay, Overlay::ModelPicker(_)));
    assert_eq!(app.composer.text(), "send this exact draft");

    let exit = app.handle_key(press(KeyCode::Enter));
    assert!(!exit);
    let pending = app
        .pending_model_selection
        .as_ref()
        .expect("selection remains pending until terminal result");
    let selection_id = pending.selection_id;
    assert!(pending.queued_submission.is_some());
    assert_eq!(app.composer.text(), "send this exact draft");
    assert!(matches!(
        control_rx.try_recv().expect("selection request").request,
        cockpit_core::daemon::proto::Request::SetActiveModel {
            selection_id: actual,
            ..
        } if actual == selection_id
    ));
    assert!(
        input_rx.try_recv().is_err(),
        "draft is not sent optimistically"
    );

    let confirmed = selection("p", "a");
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: confirmed.provider.clone(),
        model: confirmed.model.clone(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: confirmed,
                default_selection: None,
                diverged: true,
                generation: 1,
            },
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
        },
    });

    let submission = input_rx
        .try_recv()
        .expect("confirmed selection releases draft");
    assert_eq!(submission.text, "send this exact draft");
    assert_eq!(
        submission.display_text.as_deref(),
        Some("send this exact draft")
    );
    assert!(app.composer.text().is_empty());
    assert!(app.pending_model_selection.is_none());
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
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.overlay = Overlay::ModelPicker(snapshot_picker(&app));

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert!(matches!(app.overlay, Overlay::None));
    assert!(matches!(
        control_rx.try_recv().expect("selection request").request,
        cockpit_core::daemon::proto::Request::SetActiveModel {
            provider,
            model,
            persist_as_default: true,
            ..
        } if provider == "p" && model == "a"
    ));
    assert!(app.pending_model_selection.is_some());
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a for this session and saving it as the default")),
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
fn ordinary_picker_selection_stays_session_only_when_a_default_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.default_model_selection = Some(selection("old-provider", "old-model"));
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.overlay = Overlay::ModelPicker(snapshot_picker(&app));

    assert!(!app.handle_key(press(KeyCode::Enter)));
    assert!(matches!(
        control_rx.try_recv().expect("selection request").request,
        cockpit_core::daemon::proto::Request::SetActiveModel {
            provider,
            model,
            persist_as_default: false,
            ..
        } if provider == "p" && model == "a"
    ));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line == "Selecting p/a for this session…"),
        "expected session-only summary line, got {:?}",
        app.history.last()
    );
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
        selection: selection("p", "a"),
        default_selection: Some(selection("other", "old")),
        diverged: true,
        generation: 2,
    });

    assert_eq!(
        app.launch.active_model,
        Some(("p".to_string(), "a".to_string()))
    );
    assert!(app.launch.active_model_diverged);

    app.apply_event(cockpit_core::engine::TurnEvent::ActiveModelState {
        selection: selection("stale", "stale"),
        default_selection: None,
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
        selection: selection("session-p", "session-m"),
        default_selection: Some(selection("config-p", "config-m")),
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
        selection: selection("p", "a"),
        default_selection: Some(selection("p", "a")),
        diverged: false,
        generation: 3,
    });
    app.apply_event(cockpit_core::engine::TurnEvent::ActiveModelState {
        selection: selection("stale-p", "stale-m"),
        default_selection: Some(selection("config-p", "config-m")),
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
