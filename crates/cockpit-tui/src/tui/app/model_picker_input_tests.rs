use super::{App, HistoryEntry, Overlay};
use crate::tui::agent_runner::AgentRunner;
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
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

fn preference_bearing_selection(
    provider: &str,
    model: &str,
) -> cockpit_config::providers::ActiveModelRef {
    cockpit_config::providers::ActiveModelRef {
        provider: provider.to_string(),
        model: model.to_string(),
        reasoning_effort: Some(cockpit_config::providers::ActiveReasoningEffort {
            value: "high".to_string(),
        }),
        thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
        prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
    }
}

#[test]
fn passive_same_generation_terminal_result_corrects_default_and_divergence() {
    let mut app = App::new(None, false);
    let active = preference_bearing_selection("p", "selected");
    let old_default = selection("p", "old-default");
    app.apply_active_model_state(active.clone(), Some(old_default), true, 4);
    assert!(app.launch.active_model_diverged);
    assert!(app.config_drift.is_some());

    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id: uuid::Uuid::new_v4(),
        provider: active.provider.clone(),
        model: active.model.clone(),
        reasoning_effort: active
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.clone()),
        thinking_mode: active.thinking_mode,
        prompt_cache_retention: active.prompt_cache_retention,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: active.clone(),
                default_selection: Some(active.clone()),
                diverged: false,
                generation: 4,
            }),
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::Verified {
                selection: cockpit_config::providers::ActiveModelRef {
                    provider: "provider-b".into(),
                    model: "model-b".into(),
                    reasoning_effort: None,
                    thinking_mode: None,
                    prompt_cache_retention: None,
                },
                generation: 1,
                scope_label: "user".into(),
                unchanged: false,
            },
        },
    });

    assert_eq!(app.active_model_selection, Some(active.clone()));
    assert_eq!(
        app.launch.active_model,
        Some(("p".into(), "selected".into()))
    );
    assert_eq!(app.launch.provider_line, "p / selected");
    assert!(!app.launch.active_model_diverged);
    assert!(app.config_drift.is_none());
    assert_eq!(app.active_model_state_generation, 4);
    assert!(app.pending_model_selection.is_none());

    let older = selection("p", "older-event");
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id: uuid::Uuid::new_v4(),
        provider: older.provider.clone(),
        model: older.model.clone(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: older.clone(),
                default_selection: Some(older),
                diverged: false,
                generation: 3,
            }),
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
        },
    });
    assert_eq!(app.active_model_selection, Some(active));
    assert_eq!(app.active_model_state_generation, 4);
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

fn exact_queued_submission() -> super::QueuedModelSubmission {
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([1, 2, 3, 255]),
    ))
    .write_to(&mut png, image::ImageFormat::Png)
    .unwrap();
    let tag = cockpit_core::daemon::proto::TagExpansionMeta {
        tool: "read".to_string(),
        path: "src/model.rs".to_string(),
        detail: "selected lines".to_string(),
        ok: true,
    };
    super::QueuedModelSubmission {
        client_submission_id: uuid::Uuid::new_v4(),
        composer_text: "review @src/model.rs with image".to_string(),
        display: "review @src/model.rs with image".to_string(),
        submission: cockpit_core::engine::message::UserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: cockpit_core::engine::message::UserSubmissionKind::Compact,
            origin: Default::default(),
            text: "review expanded source\n\n<image>".to_string(),
            display_text: Some("review @src/model.rs with image".to_string()),
            tag_expansions: vec![tag.clone()],
            images: vec![cockpit_core::engine::message::SubmissionImage::png(
                png.into_inner(),
            )],
            forced_skill: Some("review".to_string()),
            origin_principal: Some("flycockpit:test-user".to_string()),
            job_id: Some("job-1".to_string()),
            preflight_cleaned: Some("review expanded source".to_string()),
            queue_item_ids: vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
            client_submissions: Vec::new(),
            pending_terminal_disposition: None,
            run_invocation_id: None,
            queue_target: Some(cockpit_core::engine::message::QueueTarget {
                id: "target-1".to_string(),
                agent: "Build".to_string(),
                depth: 1,
                task_call_id: Some("task-1".to_string()),
            }),
        },
        tag_expansions: vec![tag],
    }
}

fn queued_submission_value(queued: &super::QueuedModelSubmission) -> serde_json::Value {
    serde_json::json!({
        "composer_text": &queued.composer_text,
        "display": &queued.display,
        "submission": &queued.submission,
        "tag_expansions": &queued.tag_expansions,
    })
}

fn install_pending_model_submission(
    app: &mut App,
    session_id: uuid::Uuid,
    selection_id: uuid::Uuid,
    requested: cockpit_config::providers::ActiveModelRef,
    minimum_generation: u64,
    queued: super::QueuedModelSubmission,
) {
    let order_sequence = app
        .submission_order
        .enqueue(crate::tui::structured_paste::OrderedIntent::ModelSwitch(
            selection_id,
        ))
        .unwrap();
    let fence_sequence = app
        .submission_order
        .enqueue(crate::tui::structured_paste::OrderedIntent::Fence(
            queued.client_submission_id,
        ))
        .unwrap();
    app.submission_fences.insert(
        queued.client_submission_id,
        crate::tui::structured_paste::SubmissionFenceV1 {
            client_submission_id: queued.client_submission_id,
            fence_sequence,
            host: crate::tui::structured_paste::HostIdentity {
                client_instance_id: app.paste_client_instance_id,
                connection_epoch: 0,
                session_id,
                terminal_generation: app.terminal_input_generation.unwrap_or_default(),
            },
            view_generation: app.config_snapshot.generation,
            source_draft_generation: app.draft_generation,
            created_at: app.monotonic_origin.elapsed(),
            captured_composer: queued.composer_text.clone(),
            accepted_tags: Vec::new(),
            pending_git_blocks: Vec::new(),
            model: crate::tui::structured_paste::CapturedModel {
                provider_id: requested.provider.clone(),
                model_id: requested.model.clone(),
                active_model_state_generation: minimum_generation,
                image_capability_generation: app.config_snapshot.generation,
                supports_images: true,
            },
            assembled_wire_digest: None,
            slots: Vec::new(),
            retained_drafts: Vec::new(),
            lifecycle: crate::tui::structured_paste::FenceLifecycle::Ready,
        },
    );
    app.pending_model_selection = Some(super::PendingModelSelection {
        order_sequence,
        session_id: Some(session_id),
        selection_id,
        requested,
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
        minimum_generation,
        started_at: std::time::Instant::now(),
        queued_submission: Some(queued),
    });
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

#[tokio::test]
async fn model_control_is_not_sent_while_session_switch_is_pending() {
    let mut app = App::new(None, false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    let requested = preference_bearing_selection("p", "a");

    assert!(!app.request_model_selection(
        "/quick",
        requested.clone(),
        false,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
    ));

    assert!(control_rx.try_recv().is_err());
    assert!(app.pending_model_selection.is_none());
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("session switch in progress")),
        "history: {:?}",
        app.history.last()
    );
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
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a for this session; saving default")),
        "history: {:?}",
        app.history.last()
    );
    let active = cockpit_config::providers::ConfigDoc::providers_from_paths(
        &cockpit_config::dirs::config_file_paths_for_load(tmp.path()),
    )
    .active_model;
    assert_eq!(
        active, None,
        "TUI must not write config before verified terminal result"
    );
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a for this session; saving default"))
    );

    // Simulated verified terminal result — completion wording only after Applied.
    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("pending")
        .selection_id;
    let verified = cockpit_config::providers::ActiveModelRef {
        provider: "p".into(),
        model: "a".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: "p".into(),
        model: "a".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: verified.clone(),
                default_selection: Some(verified.clone()),
                diverged: false,
                generation: app
                    .pending_model_selection
                    .as_ref()
                    .map(|p| p.minimum_generation)
                    .unwrap_or(1)
                    .max(1),
            }),
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::Verified {
                selection: verified,
                generation: 1,
                scope_label: "user".into(),
                unchanged: false,
            },
        },
    });
    assert!(
        matches!(
            app.history.iter().rev().find_map(|entry| match entry {
                HistoryEntry::Plain { line } if line.contains("default for new sessions") => {
                    Some(line.as_str())
                }
                _ => None
            }),
            Some(line) if line.contains("p/a") && line.contains("user")
        ),
        "history after verified: {:?}",
        app.history.iter().rev().take(5).collect::<Vec<_>>()
    );
    assert!(
        !app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("default updated") && !line.contains("new sessions")
        )),
        "must not claim 'default updated' without verified metadata"
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
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("Selecting p/a for this session; saving default"))
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
    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    app.pending_model_selection
        .as_mut()
        .unwrap()
        .queued_submission = Some(queued);
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: "p".to_string(),
        model: "a".to_string(),
        reasoning_effort: Some("high".to_string()),
        thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
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
        .current_model_selection_retry()
        .expect("rejected selection retains the full retry intent");
    assert_eq!(retry.requested, requested);
    assert_eq!(
        retry.trigger,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker
    );
    assert_eq!(
        queued_submission_value(
            retry
                .queued_submission
                .as_ref()
                .expect("retry retains the exact queued submission")
        ),
        expected_queued
    );

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
    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    pending.queued_submission = Some(queued);

    app.open_model_picker();

    assert!(app.pending_model_selection.is_none());
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("stale pending selection retains its payload"),
        ),
        expected_queued
    );
    assert!(matches!(&app.overlay, Overlay::ModelPicker(picker)
        if picker.draft_active_model() == Some(&selection("p", "a"))));
}

#[test]
fn terminal_daemon_link_preserves_full_pending_selection_and_exact_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, _control_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_control_tx(control_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));
    let requested = preference_bearing_selection("p", "a");
    assert!(app.request_model_selection(
        "/model",
        requested.clone(),
        false,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker,
    ));
    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    app.pending_model_selection
        .as_mut()
        .unwrap()
        .queued_submission = Some(queued);
    assert!(
        app.pending_control_requests
            .values()
            .any(|request| matches!(
                request.applied,
                super::ControlApplied::ModelSelection { .. }
            ))
    );

    app.apply_event(cockpit_core::engine::TurnEvent::DaemonLinkTerminal {
        error: "protocol link ended".to_string(),
    });

    assert!(app.pending_model_selection.is_none());
    assert!(
        !app.pending_control_requests
            .values()
            .any(|request| matches!(
                request.applied,
                super::ControlApplied::ModelSelection { .. }
            ))
    );
    let retry = app
        .current_model_selection_retry()
        .expect("terminal link preserves retry state");
    assert_eq!(retry.requested, requested);
    assert_eq!(
        retry.trigger,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker
    );
    assert_eq!(
        queued_submission_value(
            retry
                .queued_submission
                .as_ref()
                .expect("terminal link preserves exact queued submission")
        ),
        expected_queued
    );
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
fn cancelling_attached_add_model_settings_immediately_reopens_picker() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.submit_after_model_selection = true;
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.overlay = Overlay::ModelPicker(
        crate::tui::model_picker::ModelPickerDialog::open_for_provider_with_failures(
            snapshot_config(),
            "p",
            app.launch.active_model.clone(),
            &app.usage_models,
            &Default::default(),
            chrono::Utc::now().timestamp(),
        )
        .unwrap(),
    );

    assert!(!app.handle_key(ctrl_press(KeyCode::Char('a'))));
    assert_eq!(app.reopen_model_picker_after_settings.as_deref(), Some("p"));

    // Escape cancels the add form; q then closes the surrounding settings
    // dialog without any changed daemon snapshot.
    assert!(!app.handle_key(press(KeyCode::Esc)));
    assert!(!app.handle_key(press(KeyCode::Char('q'))));

    assert!(matches!(app.dialog, crate::tui::settings::Dialog::None));
    assert!(app.reopen_model_picker_after_settings.is_none());
    assert!(matches!(app.overlay, Overlay::ModelPicker(_)));
    assert_eq!(
        app.refresh_reopened_model_picker_after_settings.as_deref(),
        Some("p")
    );
    assert!(app.submit_after_model_selection);

    // Dismissing the restored picker consumes the refresh correlation. A
    // later unrelated config event must not resurrect it.
    assert!(!app.handle_key(press(KeyCode::Esc)));
    assert!(matches!(app.overlay, Overlay::None));
    assert!(app.refresh_reopened_model_picker_after_settings.is_none());
    let generation = app.config_snapshot.generation.saturating_add(1);
    app.apply_event(cockpit_core::engine::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_core::daemon::proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&snapshot_config()),
        }),
    });
    assert!(matches!(app.overlay, Overlay::None));
}

#[test]
fn changed_snapshot_after_settings_close_refreshes_open_picker_inventory_once() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.config_snapshot.providers = snapshot_config();
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let mut picker = crate::tui::model_picker::ModelPickerDialog::open_for_provider_with_failures(
        snapshot_config(),
        "p",
        app.launch.active_model.clone(),
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    picker.restore_requested_selection(&selection("p", "a"));
    app.overlay = Overlay::ModelPicker(picker);

    assert!(!app.handle_key(ctrl_press(KeyCode::Char('a'))));
    assert!(!app.handle_key(press(KeyCode::Esc)));
    assert!(!app.handle_key(press(KeyCode::Char('q'))));
    let Overlay::ModelPicker(picker) = &app.overlay else {
        panic!("closing settings must restore the model picker")
    };
    assert!(picker.has_model("p", "a"));
    assert!(!picker.has_model("p", "b"));
    assert_eq!(
        app.refresh_reopened_model_picker_after_settings.as_deref(),
        Some("p")
    );

    let mut updated = snapshot_config();
    updated
        .providers
        .get_mut("p")
        .unwrap()
        .models
        .push(cockpit_config::providers::ModelEntry {
            id: "b".to_string(),
            ..Default::default()
        });
    let generation = app.config_snapshot.generation.saturating_add(1);
    app.apply_event(cockpit_core::engine::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_core::daemon::proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&updated),
        }),
    });

    let Overlay::ModelPicker(picker) = &app.overlay else {
        panic!("changed snapshot must keep the restored picker open")
    };
    assert!(picker.has_model("p", "a"));
    assert!(picker.has_model("p", "b"));
    assert_eq!(picker.draft_active_model(), Some(&selection("p", "a")));
    assert!(app.refresh_reopened_model_picker_after_settings.is_none());
}

#[test]
fn add_model_waits_through_unrelated_and_saved_snapshots_then_reopens_on_close() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.submit_after_model_selection = true;
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let mut picker = crate::tui::model_picker::ModelPickerDialog::open_for_provider_with_failures(
        snapshot_config(),
        "p",
        app.launch.active_model.clone(),
        &app.usage_models,
        &Default::default(),
        chrono::Utc::now().timestamp(),
    )
    .unwrap();
    picker.restore_requested_selection(&selection("p", "a"));
    app.overlay = Overlay::ModelPicker(picker);

    assert!(!app.handle_key(ctrl_press(KeyCode::Char('a'))));
    // An unrelated config writer pushes a newer generation while settings is
    // still open. It updates held config but cannot consume the add-model
    // causal marker or rebuild a hidden picker under the dialog.
    let generation = app.config_snapshot.generation.saturating_add(1);
    app.apply_event(cockpit_core::engine::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_core::daemon::proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&snapshot_config()),
        }),
    });

    assert_eq!(app.reopen_model_picker_after_settings.as_deref(), Some("p"));
    assert!(matches!(app.overlay, Overlay::None));
    assert!(app.dialog.is_active());
    assert!(app.submit_after_model_selection);

    // The actual provider save arrives next and is likewise held until close.
    let mut updated = snapshot_config();
    updated
        .providers
        .get_mut("p")
        .unwrap()
        .models
        .push(cockpit_config::providers::ModelEntry {
            id: "b".to_string(),
            ..Default::default()
        });
    app.apply_event(cockpit_core::engine::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_core::daemon::proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation: generation + 1,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&updated),
        }),
    });
    assert_eq!(app.reopen_model_picker_after_settings.as_deref(), Some("p"));
    assert!(matches!(app.overlay, Overlay::None));

    // Close consumes the marker exactly once and rebuilds from the latest
    // saved snapshot while preserving the original draft.
    assert!(!app.handle_key(press(KeyCode::Esc)));
    assert!(!app.handle_key(press(KeyCode::Char('q'))));
    assert!(matches!(app.dialog, crate::tui::settings::Dialog::None));
    assert!(app.reopen_model_picker_after_settings.is_none());
    let Overlay::ModelPicker(picker) = &app.overlay else {
        panic!("close must restore the picker")
    };
    assert!(picker.has_model("p", "b"));
    assert_eq!(picker.draft_active_model(), Some(&selection("p", "a")));
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
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: confirmed,
                default_selection: None,
                diverged: true,
                generation: 1,
            }),
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
fn transport_send_failure_retains_complete_queued_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, control_rx) = mpsc::channel(1);
    drop(control_rx);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let queued = exact_queued_submission();
    let expected = queued_submission_value(&queued);
    app.set_current_model_selection_retry(super::ModelSelectionRetry {
        session_id: app.launch.session_id,
        requested: selection("p", "a"),
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
        queued_submission: Some(queued),
    });

    assert!(!app.request_model_selection(
        "/quick",
        selection("p", "a"),
        false,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
    ));

    assert!(app.pending_model_selection.is_none());
    assert!(app.pending_control_requests.is_empty());
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("send failure retains queued payload"),
        ),
        expected
    );
}

#[test]
fn picker_transport_failure_does_not_report_success_or_submit_queued_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, control_rx) = mpsc::channel(1);
    drop(control_rx);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.overlay = Overlay::ModelPicker(snapshot_picker(&app));
    app.submit_after_model_selection = true;
    let queued = exact_queued_submission();
    let expected = queued_submission_value(&queued);
    app.composer.set(queued.composer_text.clone());
    app.set_current_model_selection_retry(super::ModelSelectionRetry {
        session_id: app.launch.session_id,
        requested: selection("p", "a"),
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker,
        queued_submission: Some(queued),
    });

    assert!(!app.handle_key(press(KeyCode::Enter)));

    assert!(app.pending_model_selection.is_none());
    assert!(app.pending_control_requests.is_empty());
    assert!(app.submit_after_model_selection);
    assert_eq!(app.composer.text(), "review @src/model.rs with image");
    assert!(matches!(&app.overlay, Overlay::ModelPicker(picker)
        if picker.error_text().is_some_and(|message| message.contains("request not sent"))));
    assert!(app.history.iter().all(|entry| {
        !matches!(entry, HistoryEntry::Plain { line } if line.contains("Selecting p/a"))
    }));
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("picker send failure retains exact queued payload")
        ),
        expected
    );
}

fn assert_control_failure_retains_complete_submission(
    outcome: cockpit_core::engine::ControlRequestOutcome,
) {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let queued = exact_queued_submission();
    let expected = queued_submission_value(&queued);
    app.set_current_model_selection_retry(super::ModelSelectionRetry {
        session_id: app.launch.session_id,
        requested: selection("p", "a"),
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
        queued_submission: Some(queued),
    });
    assert!(app.request_model_selection(
        "/quick",
        selection("p", "a"),
        false,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
    ));
    control_rx
        .try_recv()
        .expect("control request was delivered");
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("control request is pending");

    app.apply_control_request_outcome(request_id, outcome);

    assert!(app.pending_model_selection.is_none());
    assert!(app.pending_control_requests.is_empty());
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("control failure retains queued payload"),
        ),
        expected
    );
}

#[test]
fn rejected_ack_retains_complete_queued_submission() {
    assert_control_failure_retains_complete_submission(
        cockpit_core::engine::ControlRequestOutcome::Rejected("busy".to_string()),
    );
}

#[test]
fn not_delivered_ack_retains_complete_queued_submission() {
    assert_control_failure_retains_complete_submission(
        cockpit_core::engine::ControlRequestOutcome::NotDelivered(
            cockpit_core::engine::ControlRequestNotDelivered::RunnerTeardown,
        ),
    );
}

#[test]
fn failed_cleanup_does_not_overwrite_an_already_preserved_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    let preserved = exact_queued_submission();
    let expected = queued_submission_value(&preserved);
    let original_requested = selection("original", "selection");
    app.set_current_model_selection_retry(super::ModelSelectionRetry {
        session_id: app.launch.session_id,
        requested: original_requested.clone(),
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Cycle,
        queued_submission: Some(preserved),
    });
    let mut later = exact_queued_submission();
    later.submission.text = "later payload".to_string();
    let pending = super::PendingModelSelection {
        order_sequence: 0,
        session_id: app.launch.session_id,
        selection_id: uuid::Uuid::new_v4(),
        requested: selection("p", "a"),
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
        minimum_generation: 0,
        started_at: std::time::Instant::now(),
        queued_submission: Some(later),
    };

    app.preserve_failed_model_selection(pending);

    assert_eq!(
        app.current_model_selection_retry().unwrap().requested,
        original_requested
    );
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("original retry remains present"),
        ),
        expected
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
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: confirmed,
                default_selection: None,
                diverged: true,
                generation: 1,
            }),
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
fn confirmed_model_release_queue_full_retains_and_retries_exact_draft() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, _control_rx) = mpsc::channel(2);
    let (input_tx, mut input_rx) = mpsc::channel(1);
    input_tx
        .try_send(cockpit_core::engine::message::UserSubmission::text("channel blocker").into())
        .unwrap();
    let runner = AgentRunner::stub_with_channels(control_tx, input_tx);
    let session_id = runner.session_id();
    app.launch.session_id = Some(session_id);
    app.agent_runner = Some(Ok(runner));

    let queued = exact_queued_submission();
    app.composer.set(queued.composer_text.clone());
    let requested = preference_bearing_selection("p", "a");
    let mut expected_submission = queued.submission.clone();
    expected_submission.expected_model_state_generation = Some(1);
    expected_submission.expected_model = Some(requested.clone());
    let expected = serde_json::to_value(expected_submission).unwrap();
    let selection_id = uuid::Uuid::new_v4();
    install_pending_model_submission(
        &mut app,
        session_id,
        selection_id,
        requested.clone(),
        0,
        queued,
    );

    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: requested.provider.clone(),
        model: requested.model.clone(),
        reasoning_effort: requested
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.clone()),
        thinking_mode: requested.thinking_mode,
        prompt_cache_retention: requested.prompt_cache_retention,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: requested.clone(),
                default_selection: Some(requested),
                diverged: false,
                generation: 1,
            }),
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
        },
    });

    assert!(app.pending_model_selection.is_none());
    assert!(app.composer.is_empty());
    assert_eq!(app.retained_pre_dispatch_submissions.len(), 1);
    assert_eq!(
        serde_json::to_value(&app.retained_pre_dispatch_submissions[0].pending.submission).unwrap(),
        expected
    );

    let _blocker = input_rx.try_recv().expect("free input capacity");
    assert!(app.retry_retained_pre_dispatch_submissions());
    let crate::tui::agent_runner::RunnerInput::Submission(delivered) =
        input_rx.try_recv().expect("held draft retry delivered")
    else {
        panic!("one held draft should use one submission input");
    };
    assert_eq!(delivered.intended_session_id, session_id);
    assert_eq!(
        serde_json::to_value(delivered.submission).unwrap(),
        expected
    );
}

#[test]
fn second_submit_waiting_on_model_preserves_all_unconsumed_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;

    let held = exact_queued_submission();
    let expected_held = queued_submission_value(&held);
    app.pending_model_selection = Some(super::PendingModelSelection {
        order_sequence: 0,
        session_id: Some(uuid::Uuid::new_v4()),
        selection_id: uuid::Uuid::new_v4(),
        requested: preference_bearing_selection("p", "a"),
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker,
        minimum_generation: 0,
        started_at: std::time::Instant::now(),
        queued_submission: Some(held),
    });
    app.composer
        .set("second draft @path with spaces.rs".to_string());
    app.pending_git_blocks = vec!["git diff --binary".to_string(), "git status".to_string()];
    app.accepted_tags = vec!["path with spaces.rs".to_string()];
    let expected_git_blocks = app.pending_git_blocks.clone();
    let expected_tags = app.accepted_tags.clone();

    assert!(!app.submit_input());

    assert_eq!(app.composer.text(), "second draft @path with spaces.rs");
    assert_eq!(app.pending_git_blocks, expected_git_blocks);
    assert_eq!(app.accepted_tags, expected_tags);
    assert_eq!(
        queued_submission_value(
            app.pending_model_selection
                .as_ref()
                .and_then(|pending| pending.queued_submission.as_ref())
                .expect("the first complete payload remains held"),
        ),
        expected_held
    );
}

/// **Rejected behavior.** Plain Enter must not touch the default at all. The
/// prompt states it "sends a session-only request and never invokes the
/// effective-default mutation API" and "cannot alter `active_model` in any
/// layer" (AC7), that it "stays session-only and never performs the
/// effective-default operation" (Desired behavior, line 124), and that it
/// "remains the consciously separate session-only action" (decision 3). This
/// test previously tolerated a first-default write; it now fails
/// deterministically if that behavior returns.
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
            persist_as_default: false,
            ..
        } if provider == "p" && model == "a"
    ));
    assert!(app.pending_model_selection.is_some());
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line == "Selecting p/a for this session…"),
        "plain Enter is session-only and must not promise a default; got {:?}",
        app.history.last()
    );
    let active = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers()
        .active_model;
    assert_eq!(active, None);
}

/// **Rejected behavior.** Plain Enter must not touch the default at all. The
/// prompt states it "sends a session-only request and never invokes the
/// effective-default mutation API" and "cannot alter `active_model` in any
/// layer" (AC7), that it "stays session-only and never performs the
/// effective-default operation" (Desired behavior, line 124), and that it
/// "remains the consciously separate session-only action" (decision 3). This
/// test previously tolerated a first-default write; it now fails
/// deterministically if that behavior returns.
#[test]
fn ordinary_picker_selection_is_session_only_and_promises_no_default() {
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

#[derive(Clone, Copy)]
enum ModelEpochPath {
    AdoptReplacement,
    AdoptSameSession,
    SameRunnerReconnect,
    EventStreamLagResync,
    SessionSwitch,
}

fn assert_runner_epoch_reset_and_followup_completion(path: ModelEpochPath) {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _runtime_guard = runtime.enter();
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;

    let old_session_id = uuid::Uuid::new_v4();
    let new_session_id = match path {
        ModelEpochPath::AdoptSameSession
        | ModelEpochPath::SameRunnerReconnect
        | ModelEpochPath::EventStreamLagResync => old_session_id,
        ModelEpochPath::AdoptReplacement | ModelEpochPath::SessionSwitch => uuid::Uuid::new_v4(),
    };
    let (control_tx, mut control_rx) = mpsc::channel(2);
    let (input_tx, mut input_rx) = mpsc::channel(2);
    let mut attached_runner = Some(AgentRunner::stub_with_channels(control_tx, input_tx));
    *attached_runner
        .as_ref()
        .unwrap()
        .session_id_state
        .lock()
        .unwrap() = new_session_id;
    let attached_selection = selection("attached-provider", "attached-model");
    let attached_state = cockpit_core::daemon::proto::ActiveModelState {
        selection: attached_selection.clone(),
        default_selection: Some(attached_selection.clone()),
        diverged: false,
        generation: 0,
    };
    attached_runner.as_mut().unwrap().active_model_state = Some(attached_state.clone());
    if matches!(
        path,
        ModelEpochPath::SameRunnerReconnect | ModelEpochPath::EventStreamLagResync
    ) {
        app.agent_runner = Some(Ok(attached_runner.take().unwrap()));
    } else {
        let (old_control_tx, _old_control_rx) = mpsc::channel(2);
        let old_runner = AgentRunner::stub_with_control_tx(old_control_tx);
        *old_runner.session_id_state.lock().unwrap() = old_session_id;
        app.agent_runner = Some(Ok(old_runner));
    }
    app.launch.session_id = Some(old_session_id);
    app.active_model_state_generation = 9;
    app.apply_active_model_state(
        selection("old-provider", "old-model"),
        Some(selection("old-provider", "old-model")),
        false,
        9,
    );

    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    let pending_requested = preference_bearing_selection("pending-provider", "pending-model");
    let mut expected_submission = queued.submission.clone();
    expected_submission.expected_model_state_generation = Some(1);
    expected_submission.expected_model = Some(pending_requested.clone());
    let expected_submission = serde_json::to_value(expected_submission).unwrap();
    app.composer.set(queued.composer_text.clone());
    let old_selection_id = uuid::Uuid::new_v4();
    install_pending_model_submission(
        &mut app,
        old_session_id,
        old_selection_id,
        pending_requested.clone(),
        9,
        queued,
    );
    app.pending_control_requests.insert(
        cockpit_core::engine::ControlRequestId(77),
        super::PendingControlRequest {
            label: "/quick".to_string(),
            applied: super::ControlApplied::ModelSelection {
                selection_id: old_selection_id,
            },
        },
    );

    let automatically_retried = matches!(
        path,
        ModelEpochPath::SameRunnerReconnect | ModelEpochPath::EventStreamLagResync
    );
    match path {
        ModelEpochPath::AdoptReplacement | ModelEpochPath::AdoptSameSession => {
            app.adopt_runner(Ok(attached_runner.take().unwrap()));
        }
        ModelEpochPath::SameRunnerReconnect => {
            app.apply_event(cockpit_core::engine::TurnEvent::DaemonLinkReconnected {
                active_model_state: Some(attached_state.clone()),
            });
        }
        ModelEpochPath::EventStreamLagResync => {
            app.apply_event(cockpit_core::engine::TurnEvent::DaemonLinkResynced {
                active_model_state: Some(attached_state.clone()),
            });
        }
        ModelEpochPath::SessionSwitch => {
            // The production session-switch response is authoritative before
            // the next control can be sent. The stub is installed afterwards
            // because only live runners carry swappable transport internals.
            app.agent_runner.take();
            app.apply_session_switch_outcome(crate::tui::agent_runner::SessionSwitchOutcome {
                target: crate::tui::agent_runner::SessionTarget::Resume {
                    session_id: new_session_id,
                    since_seq: None,
                },
                session_id: new_session_id,
                short_id: "new001".to_string(),
                active_agent: "Build".to_string(),
                active_agent_path: vec!["Build".to_string()],
                last_applied_seq: None,
                foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
                active_model_state: Some(attached_state.clone()),
                project_id: "project".to_string(),
                history: Vec::new(),
                paused_work: Vec::new(),
                repair_required: None,
                btw_fork: None,
                daemon_version: "test".to_string(),
                daemon_compatible: true,
                attachment_epoch: 0,
                transition_guard: None,
            });
            app.agent_runner = Some(Ok(attached_runner.take().unwrap()));
        }
    }

    assert_eq!(app.active_model_state_generation, 0);
    assert_eq!(
        app.active_model_selection.as_ref(),
        Some(&attached_selection)
    );
    assert_eq!(app.launch.session_id, Some(new_session_id));
    assert_eq!(app.pending_model_selection.is_some(), automatically_retried);
    // Attaching also refreshes daemon capabilities, so unrelated control
    // requests may legitimately be in flight.  What must not survive an
    // epoch transition is the old model-selection request; reconnect paths
    // replace it with a request carrying a new selection id.
    assert!(!app.pending_control_requests.values().any(|request| {
        matches!(
            request.applied,
            super::ControlApplied::ModelSelection { selection_id }
                if selection_id == old_selection_id
        )
    }));
    assert_eq!(
        app.pending_control_requests.values().any(|request| {
            matches!(
                request.applied,
                super::ControlApplied::ModelSelection { .. }
            )
        }),
        automatically_retried
    );
    let preserved = if automatically_retried {
        let pending = app
            .pending_model_selection
            .as_ref()
            .expect("reconnect immediately retries the retained model intent");
        assert_eq!(pending.requested, pending_requested);
        pending
            .queued_submission
            .as_ref()
            .expect("automatic retry retains queued submission")
    } else {
        let retry = app
            .retry_model_selections
            .get(&Some(old_session_id))
            .expect("runner epoch change retains retry intent for its owning session");
        assert_eq!(retry.requested, pending_requested);
        retry
            .queued_submission
            .as_ref()
            .expect("runner epoch change retains queued submission")
    };
    assert_eq!(queued_submission_value(preserved), expected_queued);
    if old_session_id != new_session_id {
        assert!(
            app.current_model_selection_retry().is_none(),
            "the replacement session cannot see the old session's retry"
        );
        assert!(app.request_model_selection(
            "/quick",
            pending_requested,
            false,
            cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
        ));
        assert!(
            app.pending_model_selection
                .as_ref()
                .expect("replacement selection is pending")
                .queued_submission
                .is_none(),
            "the replacement session must not adopt the old exact payload"
        );
        assert!(input_rx.try_recv().is_err());
        return;
    }
    let requested = pending_requested;
    if !automatically_retried {
        app.open_model_picker();
        assert!(matches!(&app.overlay, Overlay::ModelPicker(picker)
            if picker.draft_active_model() == Some(&requested)));
        assert!(app.request_model_selection(
            "/quick",
            requested.clone(),
            false,
            cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
        ));
    }
    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("follow-up selection is pending")
        .selection_id;
    assert_eq!(
        app.pending_model_selection
            .as_ref()
            .expect("follow-up selection is pending")
            .minimum_generation,
        0
    );
    control_rx.try_recv().expect("follow-up control delivered");

    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: requested.provider.clone(),
        model: requested.model.clone(),
        reasoning_effort: requested
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.clone()),
        thinking_mode: requested.thinking_mode,
        prompt_cache_retention: requested.prompt_cache_retention,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: requested.clone(),
                default_selection: Some(requested),
                diverged: false,
                generation: 1,
            }),
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
        },
    });

    let delivered = input_rx
        .try_recv()
        .expect("generation-one result releases exact queued submission");
    assert_eq!(
        serde_json::to_value(delivered.submission.clone()).unwrap(),
        expected_submission
    );
    assert_eq!(app.active_model_state_generation, 1);
    assert!(app.pending_model_selection.is_none());
    assert!(app.current_model_selection_retry().is_none());
}

#[test]
fn session_replacement_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::AdoptReplacement);
}

#[test]
fn same_session_reconnect_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::AdoptSameSession);
}

#[test]
fn same_runner_daemon_reconnect_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::SameRunnerReconnect);
}

#[test]
fn event_stream_lag_resync_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::EventStreamLagResync);
}

#[test]
fn session_switch_outcome_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::SessionSwitch);
}

#[test]
fn session_switch_drains_queued_old_epoch_events_before_authoritative_attach() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let transition_gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let transition_guard = runtime.block_on(transition_gate.clone().lock_owned());
    let _runtime_guard = runtime.enter();
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let old_session_id = uuid::Uuid::new_v4();
    let new_session_id = uuid::Uuid::new_v4();
    let (control_tx, mut control_rx) = mpsc::channel(4);
    let (input_tx, mut input_rx) = mpsc::channel(2);
    let mut runner = AgentRunner::stub_with_channels(control_tx, input_tx);
    runner.last_applied_seq = Some(std::sync::Arc::new(std::sync::Mutex::new(Some(8))));
    *runner.session_id_state.lock().unwrap() = old_session_id;
    let event_queue = runner.events.clone();
    app.agent_runner = Some(Ok(runner));
    app.launch.session_id = Some(old_session_id);
    app.apply_active_model_state(
        selection("old-provider", "old-model"),
        Some(selection("old-provider", "old-model")),
        false,
        8,
    );

    let requested = preference_bearing_selection("pending-provider", "pending-model");
    let queued = exact_queued_submission();
    let expected_submission = serde_json::to_value(&queued.submission).unwrap();
    let old_selection_id = uuid::Uuid::new_v4();
    install_pending_model_submission(
        &mut app,
        old_session_id,
        old_selection_id,
        requested.clone(),
        8,
        queued,
    );
    app.pending_control_requests.insert(
        cockpit_core::engine::ControlRequestId(88),
        super::PendingControlRequest {
            label: "/quick".to_string(),
            applied: super::ControlApplied::ModelSelection {
                selection_id: old_selection_id,
            },
        },
    );
    event_queue
        .lock()
        .unwrap()
        .push(crate::tui::agent_runner::QueuedTurnEvent {
            attachment_epoch: 0,
            event: cockpit_core::engine::TurnEvent::ActiveModelState {
                selection: selection("stale-provider", "stale-model"),
                default_selection: Some(selection("stale-provider", "stale-model")),
                diverged: false,
                generation: 9,
            },
        });

    let attached_selection = selection("attached-provider", "attached-model");
    app.apply_session_switch_outcome(crate::tui::agent_runner::SessionSwitchOutcome {
        target: crate::tui::agent_runner::SessionTarget::Resume {
            session_id: new_session_id,
            since_seq: None,
        },
        session_id: new_session_id,
        short_id: "new001".to_string(),
        active_agent: "Build".to_string(),
        active_agent_path: vec!["Build".to_string()],
        last_applied_seq: None,
        foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
        active_model_state: Some(cockpit_core::daemon::proto::ActiveModelState {
            selection: attached_selection.clone(),
            default_selection: Some(attached_selection.clone()),
            diverged: false,
            generation: 0,
        }),
        project_id: "project".to_string(),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        attachment_epoch: 0,
        transition_guard: Some(transition_guard),
    });

    assert!(transition_gate.try_lock().is_ok());
    assert!(event_queue.lock().unwrap().is_empty());
    assert_eq!(app.active_model_state_generation, 0);
    assert_eq!(app.active_model_selection, Some(attached_selection));
    assert_eq!(app.launch.session_id, Some(new_session_id));
    let preserved_retry = app
        .retry_model_selections
        .get(&Some(old_session_id))
        .expect("old runner selection is retained for the old session");
    assert_eq!(preserved_retry.requested, requested);
    assert_eq!(
        serde_json::to_value(
            &preserved_retry
                .queued_submission
                .as_ref()
                .expect("old exact payload is retained")
                .submission
        )
        .unwrap(),
        expected_submission
    );
    assert!(app.current_model_selection_retry().is_none());

    assert!(app.request_model_selection(
        "/quick",
        requested.clone(),
        false,
        cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
    ));
    control_rx
        .try_recv()
        .expect("generation-one selection request delivered");
    let selection_id = app.pending_model_selection.as_ref().unwrap().selection_id;
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: requested.provider.clone(),
        model: requested.model.clone(),
        reasoning_effort: requested
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.clone()),
        thinking_mode: requested.thinking_mode,
        prompt_cache_retention: requested.prompt_cache_retention,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: requested.clone(),
                default_selection: Some(requested),
                diverged: false,
                generation: 1,
            }),
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
        },
    });
    assert!(
        input_rx.try_recv().is_err(),
        "the replacement session must not receive the old exact payload"
    );
    assert!(
        app.retry_model_selections
            .contains_key(&Some(old_session_id))
    );
    assert_eq!(app.active_model_state_generation, 1);
}

/// Build the exact state a Ctrl+Enter picker selection leaves behind: one
/// correlated pending intent, no local config write, and progress-only wording.
fn picker_app_awaiting_default_terminal(
    tmp: &tempfile::TempDir,
) -> (
    App,
    mpsc::Receiver<crate::tui::agent_runner::ControlRequest>,
    uuid::Uuid,
) {
    let cockpit = tmp.path().join("config").join("cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, control_rx) = mpsc::channel(4);
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
    assert!(!app.handle_key(ctrl_press(KeyCode::Enter)));
    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("pending intent")
        .selection_id;
    (app, control_rx, selection_id)
}

/// AC8: `unchanged`-verified is distinguishable from `applied`-verified and
/// still never claims that a write occurred.
#[test]
fn picker_unchanged_verified_default_reports_already_set_without_claiming_a_write() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let (mut app, _control_rx, selection_id) = picker_app_awaiting_default_terminal(&tmp);

    let verified = selection("p", "a");
    let minimum_generation = app
        .pending_model_selection
        .as_ref()
        .map(|pending| pending.minimum_generation)
        .unwrap_or(1)
        .max(1);
    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: "p".into(),
        model: "a".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Applied {
            active_state: Box::new(cockpit_core::daemon::proto::ModelSelectionActiveState {
                selection: verified.clone(),
                default_selection: Some(verified.clone()),
                diverged: false,
                generation: minimum_generation,
            }),
            default_update: cockpit_core::daemon::proto::DefaultModelUpdateOutcome::Verified {
                selection: verified,
                generation: 1,
                scope_label: "user".into(),
                unchanged: true,
            },
        },
    });

    assert!(
        app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line }
                if line.contains("default for new sessions already set") && line.contains("user")
        )),
        "history: {:?}",
        app.history
    );
    assert!(
        !app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("and set it as the default")
        )),
        "an unchanged result must not claim a write occurred"
    );
}

/// AC4/AC8: a rejected default retains the picker intent, states that the
/// default did not change, and writes nothing locally.
#[test]
fn picker_rejected_default_retains_intent_and_states_the_default_did_not_change() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let (mut app, _control_rx, selection_id) = picker_app_awaiting_default_terminal(&tmp);

    app.apply_event(cockpit_core::engine::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: "p".into(),
        model: "a".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
        outcome: cockpit_core::daemon::proto::ModelSelectionOutcome::Rejected {
            user_message: "Could not make `p/a` the default for new sessions — the highest-precedence config layer (project) is not writable. The default was not changed and this session kept its model."
                .into(),
            diagnostic_code: "effective_default_target_unwritable".into(),
        },
    });

    assert!(
        matches!(&app.overlay, Overlay::ModelPicker(picker)
        if picker.error_text().is_some_and(|error| {
            error.contains("The default was not changed") && error.contains("not writable")
        })),
        "a rejection retains the picker intent and shows the actionable daemon error"
    );
    assert!(
        !app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("set it as the default")
        )),
        "a rejection must never render completion wording"
    );
    let active = cockpit_config::providers::ConfigDoc::providers_from_paths(
        &cockpit_config::dirs::config_file_paths_for_load(tmp.path()),
    )
    .active_model;
    assert_eq!(active, None, "a rejected default writes no config bytes");
}

/// A standalone Settings default update is correlated by its own operation id
/// and never touches session model state.
#[test]
fn standalone_default_model_result_is_correlated_and_leaves_the_session_alone() {
    let mut app = App::new(None, false);
    let mine = uuid::Uuid::new_v4();
    app.pending_default_model_update_id = Some(mine);

    // A late result for a different operation is ignored entirely.
    app.apply_event(cockpit_core::engine::TurnEvent::DefaultModelUpdateResult {
        default_update_id: uuid::Uuid::new_v4(),
        outcome: cockpit_core::daemon::proto::DefaultModelStandaloneOutcome::Applied {
            selection: Some(selection("other", "model")),
            generation: 1,
            scope_label: "user".into(),
            unchanged: false,
        },
    });
    assert_eq!(app.pending_default_model_update_id, Some(mine));
    assert!(
        !app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("other/model")
        )),
        "a stale terminal event must not produce misleading feedback"
    );
    assert!(app.pending_model_selection.is_none());

    app.apply_event(cockpit_core::engine::TurnEvent::DefaultModelUpdateResult {
        default_update_id: mine,
        outcome: cockpit_core::daemon::proto::DefaultModelStandaloneOutcome::Applied {
            selection: Some(selection("p", "a")),
            generation: 2,
            scope_label: "project".into(),
            unchanged: false,
        },
    });
    assert_eq!(app.pending_default_model_update_id, None);
    assert!(
        app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line }
                if line.contains("Default model for new sessions set to p/a")
                    && line.contains("project")
        )),
        "history: {:?}",
        app.history
    );
    assert!(
        app.pending_model_selection.is_none(),
        "a Settings default update never creates session model intent"
    );

    // A rejection claims no change and names only a scope.
    let second = uuid::Uuid::new_v4();
    app.pending_default_model_update_id = Some(second);
    app.apply_event(cockpit_core::engine::TurnEvent::DefaultModelUpdateResult {
        default_update_id: second,
        outcome: cockpit_core::daemon::proto::DefaultModelStandaloneOutcome::Rejected {
            user_message: "the highest-precedence config layer (project) is not writable".into(),
            diagnostic_code: "effective_default_target_unwritable".into(),
        },
    });
    assert!(
        app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("Default model was not changed")
        )),
        "history: {:?}",
        app.history
    );
}
