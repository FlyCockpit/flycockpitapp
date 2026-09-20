//! Composer model menu protocol tests ported from deleted overlay picker tests.

use super::composer_controls::ComposerPickerStatus;
use super::{App, HistoryEntry};
use crate::tui::agent_runner::AgentRunner;
use crate::tui::composer_controls::ComposerControlKind;
use cockpit_client::submission::ClientUserSubmission;
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
    let tag = cockpit_proto::TagExpansionMeta {
        tool: "read".to_string(),
        path: "src/model.rs".to_string(),
        detail: "selected lines".to_string(),
        ok: true,
    };
    super::QueuedModelSubmission {
        client_submission_id: uuid::Uuid::new_v4(),
        composer_text: "review @src/model.rs with image".to_string(),
        display: "review @src/model.rs with image".to_string(),
        submission: ClientUserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: cockpit_client::submission::UserSubmissionKind::Compact,
            origin: Default::default(),
            text: "review expanded source\n\n<image>".to_string(),
            display_text: Some("review @src/model.rs with image".to_string()),
            tag_expansions: vec![tag.clone()],
            images: vec![cockpit_client::image_upload::SubmissionImage::png(
                png.into_inner(),
            )],
            media: Vec::new(),
            forced_skill: Some("review".to_string()),
            origin_principal: Some("flycockpit:test-user".to_string()),
            job_id: Some("job-1".to_string()),
            preflight_cleaned: Some("review expanded source".to_string()),
            queue_item_ids: vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
            client_submissions: Vec::new(),
            pending_terminal_disposition: None,
            run_invocation_id: None,
            queue_target: Some(cockpit_proto::QueueTarget {
                id: "target-1".to_string(),
                agent: "Build".to_string(),
                depth: 1,
                task_call_id: Some("task-1".to_string()),
            }),
            delivery_class: Default::default(),
            delivery_class_override: None,
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
        trigger: cockpit_proto::ActiveModelSwitchTrigger::Quick,
        minimum_generation,
        started_at: std::time::Instant::now(),
        queued_submission: Some(queued),
    });
}

fn seed_model_selection_retry(app: &mut App, retry: super::ModelSelectionRetry) {
    let session_id = retry.session_id;
    app.retry_model_selections.insert(session_id, retry);
}

const ADD_MODEL_ITEM_ID: &str = "\u{0}add-model";

fn seed_p_provider_snapshot(app: &mut App) {
    app.config_snapshot.providers = snapshot_config();
}

fn open_composer_model_menu_root(app: &mut App) {
    seed_p_provider_snapshot(app);
    app.open_composer_picker_from_chord(ComposerControlKind::Model);
}

fn open_composer_model_menu_for_p_with_selection(
    app: &mut App,
    highlight: &cockpit_config::providers::ActiveModelRef,
) {
    seed_p_provider_snapshot(app);
    app.open_model_menu_highlighting(Some(highlight));
}

fn composer_model_menu_open(app: &App) -> bool {
    app.composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.kind == ComposerControlKind::Model)
}

fn composer_menu_has_model(app: &App, provider: &str, model: &str) -> bool {
    app.composer_controls.picker.as_ref().is_some_and(|picker| {
        picker.categories.iter().any(|category| {
            category.id == provider && category.items.iter().any(|item| item.id == model)
        })
    })
}

fn composer_menu_highlighted(app: &App) -> Option<cockpit_config::providers::ActiveModelRef> {
    app.composer_controls.picker.as_ref().and_then(|picker| {
        picker.categories.get(picker.category).and_then(|category| {
            category.items.get(picker.cursor).map(|item| {
                cockpit_config::providers::ActiveModelRef {
                    provider: category.id.clone(),
                    model: item.id.clone(),
                    reasoning_effort: item.selected_reasoning_effort.clone(),
                    thinking_mode: item.selected_thinking_mode,
                    prompt_cache_retention: item.selected_prompt_cache_retention,
                }
            })
        })
    })
}

fn composer_menu_error_text(app: &App) -> Option<String> {
    app.composer_controls.picker.as_ref().and_then(|picker| {
        if picker.status == ComposerPickerStatus::Unavailable {
            picker.status_text.clone()
        } else {
            None
        }
    })
}

fn select_first_model_in_composer_menu(app: &mut App) {
    open_composer_model_menu_root(app);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
}

fn trigger_add_model_from_composer_menu(app: &mut App) {
    if let Some(picker) = app.composer_controls.picker.as_mut() {
        if picker.level == 0 {
            if let Some(index) = picker.categories.iter().position(|c| c.id == "p") {
                picker.level = 1;
                picker.category = index;
            }
        }
        if let Some(category) = picker.categories.get(picker.category)
            && let Some(index) = category
                .items
                .iter()
                .position(|item| item.id == ADD_MODEL_ITEM_ID)
        {
            picker.cursor = index;
        }
    }
    assert!(!app.handle_key(press(KeyCode::Enter)));
}

fn composer_app_awaiting_default_terminal(
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
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers();
    select_first_model_in_composer_menu(&mut app);
    assert!(!app.handle_key(ctrl_press(KeyCode::Enter)));
    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("pending intent")
        .selection_id;
    (app, control_rx, selection_id)
}
#[test]
fn composer_model_menu_bootstrap_failure_stays_inline_without_false_success() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new_with_bootstrap_config(Some(tmp.path()), false);
    App::prepare_runner_attach_harness(&mut app);
    app.dialog = crate::tui::settings::Dialog::None;
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers();
    open_composer_model_menu_root(&mut app);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|p| p.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    let history_len = app.history.len();
    let usage_len = app.pending_usage.len();

    let exit = app.handle_key(press(KeyCode::Enter));
    for _ in 0..50 {
        app.drain_async_actions();
        if composer_model_menu_open(&app)
            && composer_menu_error_text(&app)
                .as_deref()
                .is_some_and(|error| {
                    error
                        .to_ascii_lowercase()
                        .contains("could not start a session")
                })
            && app.async_actions.pending_count() == 0
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    assert!(!exit);
    assert!(
        composer_model_menu_open(&app)
            && composer_menu_error_text(&app)
                .as_deref()
                .is_some_and(|error| {
                    error
                        .to_ascii_lowercase()
                        .contains("could not start a session")
                })
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
fn composer_model_menu_make_default_sends_correlated_request_without_local_write() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join("config").join("cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers();
    select_first_model_in_composer_menu(&mut app);
    let exit = app.handle_key(ctrl_press(KeyCode::Enter));
    assert!(!exit);
    let request = control_rx
        .try_recv()
        .expect("selection request queued")
        .request;
    assert!(matches!(
        request,
        cockpit_proto::Request::SetActiveModel {
            provider,
            model,
            persist_as_default: true,
            ..
        } if provider == "p" && model == "a"
    ));
    assert!(app.pending_model_selection.is_some());
    let active = cockpit_config::providers::ConfigDoc::providers_from_paths(
        &cockpit_config::dirs::config_file_paths_for_load(tmp.path()),
    )
    .active_model;
    assert_eq!(
        active, None,
        "TUI must not write config before verified terminal result"
    );
    assert_eq!(app.usage_models.get("p/a"), Some(&1));

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
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: "p".into(),
            model: "a".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
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
                default_update: cockpit_proto::DefaultModelUpdateOutcome::Verified {
                    selection: verified,
                    generation: 1,
                    scope_label: "user".into(),
                    unchanged: false,
                },
            },
        },
    );
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
fn composer_model_menu_default_intent_waits_for_daemon_without_local_write() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let source = tempfile::tempdir().unwrap();
    let source_config = source.path().join("config.json");
    write_config(&source_config);
    _env.set_cockpit_config(&tmp.path().join("missing.json"));
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&source_config)
        .unwrap()
        .providers();
    select_first_model_in_composer_menu(&mut app);
    let exit = app.handle_key(ctrl_press(KeyCode::Enter));
    assert!(!exit);
    assert!(control_rx.try_recv().is_ok());
    assert!(app.pending_model_selection.is_some());
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
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
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers();
    let (control_tx, _control_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_control_tx(control_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));

    app.launch.active_model = Some(("old-provider".to_string(), "old-model".to_string()));
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
        cockpit_proto::ActiveModelSwitchTrigger::Picker,
    ));
    let selection_id = app.pending_model_selection.as_ref().unwrap().selection_id;
    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    app.pending_model_selection
        .as_mut()
        .unwrap()
        .queued_submission = Some(queued);
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: "p".to_string(),
            model: "a".to_string(),
            reasoning_effort: Some("high".to_string()),
            thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
            prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
            outcome: cockpit_proto::ModelSelectionOutcome::Rejected {
                user_message: "provider rejected the selection".to_string(),
                diagnostic_code: "model_switch_rejected".to_string(),
            },
        },
    );
    assert!(
        composer_model_menu_open(&app)
            && composer_menu_error_text(&app).as_deref() == Some("provider rejected the selection")
    );
    let retry = app
        .current_model_selection_retry()
        .expect("rejected selection retains the full retry intent");
    assert_eq!(retry.requested, requested);
    assert_eq!(
        retry.trigger,
        cockpit_proto::ActiveModelSwitchTrigger::Picker
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
fn composer_model_menu_reopening_expires_stale_request_and_carries_queued_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    seed_p_provider_snapshot(&mut app);
    let (control_tx, _control_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_control_tx(control_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));
    assert!(app.request_model_selection(
        "/model",
        selection("p", "a"),
        false,
        cockpit_proto::ActiveModelSwitchTrigger::Picker,
    ));
    let pending = app.pending_model_selection.as_mut().unwrap();
    pending.started_at = std::time::Instant::now() - std::time::Duration::from_secs(61);
    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    pending.queued_submission = Some(queued);

    app.open_model_menu_highlighting(None);

    assert!(app.pending_model_selection.is_none());
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("stale pending selection retains its payload"),
        ),
        expected_queued
    );
    assert_eq!(
        composer_menu_highlighted(&app).as_ref(),
        Some(&selection("p", "a"))
    );
}
#[test]
fn composer_model_menu_adding_model_from_recovery_preserves_auto_submit_intent() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    seed_p_provider_snapshot(&mut app);
    open_composer_model_menu_for_p_with_selection(&mut app, &selection("p", "a"));
    app.submit_after_model_selection = true;
    trigger_add_model_from_composer_menu(&mut app);

    assert!(app.submit_after_model_selection);
    assert_eq!(
        app.reopen_composer_model_after_settings.as_deref(),
        Some("p")
    );
    assert!(!matches!(app.dialog, crate::tui::settings::Dialog::None));
}
#[test]
fn composer_model_menu_cancelling_attached_add_model_settings_immediately_reopens_menu() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    seed_p_provider_snapshot(&mut app);
    open_composer_model_menu_for_p_with_selection(&mut app, &selection("p", "a"));
    app.submit_after_model_selection = true;
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    trigger_add_model_from_composer_menu(&mut app);
    assert_eq!(
        app.reopen_composer_model_after_settings.as_deref(),
        Some("p")
    );

    // Escape cancels the add form; q then closes the surrounding settings
    // dialog without any changed daemon snapshot.
    assert!(!app.handle_key(press(KeyCode::Esc)));
    assert!(!app.handle_key(press(KeyCode::Char('q'))));

    assert!(matches!(app.dialog, crate::tui::settings::Dialog::None));
    assert!(app.reopen_composer_model_after_settings.is_none());
    assert!(composer_model_menu_open(&app));
    assert_eq!(
        app.refresh_reopened_composer_model_after_settings
            .as_deref(),
        Some("p")
    );
    assert!(app.submit_after_model_selection);

    // Dismissing the restored picker consumes the refresh correlation. A
    // later unrelated config event must not resurrect it.
    app.close_composer_picker();
    assert!(!composer_model_menu_open(&app));
    assert!(app.refresh_reopened_composer_model_after_settings.is_none());
    let generation = app.config_snapshot.generation.saturating_add(1);
    app.apply_event(cockpit_client::presentation::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&snapshot_config()),
        }),
    });
    assert!(!composer_model_menu_open(&app));
}
#[test]
fn composer_model_menu_changed_snapshot_after_settings_close_refreshes_inventory_once() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    seed_p_provider_snapshot(&mut app);
    open_composer_model_menu_for_p_with_selection(&mut app, &selection("p", "a"));
    app.config_snapshot.providers = snapshot_config();
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    trigger_add_model_from_composer_menu(&mut app);
    assert!(!app.handle_key(press(KeyCode::Esc)));
    assert!(!app.handle_key(press(KeyCode::Char('q'))));
    assert!(
        composer_model_menu_open(&app),
        "composer model menu must be open"
    );
    assert!(composer_menu_has_model(&app, "p", "a"));
    assert!(!composer_menu_has_model(&app, "p", "b"));
    assert_eq!(
        app.refresh_reopened_composer_model_after_settings
            .as_deref(),
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
    app.apply_event(cockpit_client::presentation::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&updated),
        }),
    });

    assert!(
        composer_model_menu_open(&app),
        "composer model menu must be open"
    );
    assert!(composer_menu_has_model(&app, "p", "a"));
    assert!(composer_menu_has_model(&app, "p", "b"));
    assert_eq!(
        composer_menu_highlighted(&app).as_ref(),
        Some(&selection("p", "a"))
    );
    assert!(app.refresh_reopened_composer_model_after_settings.is_none());
}
#[test]
fn composer_model_menu_add_waits_through_unrelated_and_saved_snapshots_then_reopens_on_close() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    seed_p_provider_snapshot(&mut app);
    open_composer_model_menu_for_p_with_selection(&mut app, &selection("p", "a"));
    app.submit_after_model_selection = true;
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    trigger_add_model_from_composer_menu(&mut app);
    // An unrelated config writer pushes a newer generation while settings is
    // still open. It updates held config but cannot consume the add-model
    // causal marker or rebuild a hidden picker under the dialog.
    let generation = app.config_snapshot.generation.saturating_add(1);
    app.apply_event(cockpit_client::presentation::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&snapshot_config()),
        }),
    });

    assert_eq!(
        app.reopen_composer_model_after_settings.as_deref(),
        Some("p")
    );
    assert!(!composer_model_menu_open(&app));
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
    app.apply_event(cockpit_client::presentation::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation: generation + 1,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&updated),
        }),
    });
    assert_eq!(
        app.reopen_composer_model_after_settings.as_deref(),
        Some("p")
    );
    assert!(!composer_model_menu_open(&app));

    // Close consumes the marker exactly once and rebuilds from the latest
    // saved snapshot while preserving the original draft.
    assert!(!app.handle_key(press(KeyCode::Esc)));
    assert!(!app.handle_key(press(KeyCode::Char('q'))));
    assert!(matches!(app.dialog, crate::tui::settings::Dialog::None));
    assert!(app.reopen_composer_model_after_settings.is_none());
    assert!(
        composer_model_menu_open(&app),
        "composer model menu must be open"
    );
    assert!(composer_menu_has_model(&app, "p", "b"));
    assert_eq!(
        composer_menu_highlighted(&app).as_ref(),
        Some(&selection("p", "a"))
    );
}
#[test]
fn composer_model_menu_quick_delivery_rejection_does_not_open_menu() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
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
        cockpit_client::presentation::ControlRequestOutcome::Rejected("busy".to_string()),
    );

    assert!(app.pending_model_selection.is_none());
    assert!(!composer_model_menu_open(&app));
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line.contains("/quick: daemon rejected request: busy"))
    );
}
#[test]
fn composer_model_menu_transport_failure_does_not_report_success_or_submit_queued_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, control_rx) = mpsc::channel(1);
    drop(control_rx);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    open_composer_model_menu_root(&mut app);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|p| p.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    app.submit_after_model_selection = true;
    let queued = exact_queued_submission();
    let expected = queued_submission_value(&queued);
    app.composer.set(queued.composer_text.clone());
    let session_id = app.launch.session_id;
    seed_model_selection_retry(
        &mut app,
        super::ModelSelectionRetry {
            session_id,
            requested: selection("p", "a"),
            trigger: cockpit_proto::ActiveModelSwitchTrigger::Picker,
            queued_submission: Some(queued),
        },
    );

    assert!(!app.handle_key(press(KeyCode::Enter)));

    assert!(app.pending_model_selection.is_none());
    assert!(app.pending_control_requests.is_empty());
    assert!(app.submit_after_model_selection);
    assert_eq!(app.composer.text(), "review @src/model.rs with image");
    assert!(
        composer_model_menu_open(&app)
            && composer_menu_error_text(&app)
                .as_deref()
                .is_some_and(|message| message.contains("request not sent"))
    );
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
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    let (input_tx, mut input_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_channels(control_tx, input_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));
    app.composer.set("send this exact draft".to_string());

    assert!(!app.submit_input());
    assert!(composer_model_menu_open(&app));
    assert_eq!(app.composer.text(), "send this exact draft");

    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
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
        cockpit_proto::Request::SetActiveModel {
            selection_id: actual,
            ..
        } if actual == selection_id
    ));
    assert!(
        input_rx.try_recv().is_err(),
        "draft is not sent optimistically"
    );

    let confirmed = selection("p", "a");
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: confirmed.provider.clone(),
            model: confirmed.model.clone(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: confirmed,
                    default_selection: None,
                    diverged: true,
                    generation: 1,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::NotRequested,
            },
        },
    );

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
fn composer_model_menu_selection_records_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers();
    open_composer_model_menu_root(&mut app);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|p| p.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert!(matches!(
        control_rx.try_recv().expect("selection request").request,
        cockpit_proto::Request::SetActiveModel {
            provider,
            model,
            persist_as_default: false,
            ..
        } if provider == "p" && model == "a"
    ));
    assert!(app.pending_model_selection.is_some());
    assert_eq!(app.usage_models.get("p/a"), Some(&1));
    let active = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers()
        .active_model;
    assert_eq!(active, None);
}
#[test]
fn composer_model_menu_ordinary_selection_is_session_only_and_promises_no_default() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    write_config(&config_path);

    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    app.config_snapshot.providers = cockpit_config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .providers();
    open_composer_model_menu_root(&mut app);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|p| p.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    assert!(!app.handle_key(press(KeyCode::Enter)));
    assert!(matches!(
        control_rx.try_recv().expect("selection request").request,
        cockpit_proto::Request::SetActiveModel {
            provider,
            model,
            persist_as_default: false,
            ..
        } if provider == "p" && model == "a"
    ));
}
#[test]
fn config_drift_stale_generation_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    write_config(&cockpit.join("config.json"));

    let mut app = App::new(Some(tmp.path()), false);
    app.apply_event(cockpit_client::presentation::TurnEvent::ActiveModelState {
        selection: selection("p", "a"),
        default_selection: Some(selection("p", "a")),
        diverged: false,
        generation: 3,
    });
    app.apply_event(cockpit_client::presentation::TurnEvent::ActiveModelState {
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
#[test]
fn session_switch_drains_queued_old_epoch_events_before_authoritative_attach() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let transition_gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let transition_guard = runtime.block_on(transition_gate.clone().lock_owned());
    let _runtime_guard = runtime.enter();
    let mut app = App::new(Some(tmp.path()), false);
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
        cockpit_client::presentation::ControlRequestId(88),
        super::PendingControlRequest::new(
            "/quick",
            super::ControlApplied::ModelSelection {
                selection_id: old_selection_id,
            },
        ),
    );
    event_queue
        .lock()
        .unwrap()
        .push(crate::tui::agent_runner::QueuedTurnEvent {
            attachment_epoch: 0,
            event: cockpit_client::presentation::TurnEvent::ActiveModelState {
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
        session_entry_mode: cockpit_core::daemon::proto::SessionEntryMode::Code,
        promoted_from_ephemeral: false,
        short_id: "new001".to_string(),
        active_agent: "Build".to_string(),
        active_agent_path: vec!["Build".to_string()],
        last_applied_seq: None,
        foreground_target: Some(cockpit_proto::QueueTarget::root("Build")),
        active_model_state: Some(cockpit_proto::ActiveModelState {
            selection: attached_selection.clone(),
            default_selection: Some(attached_selection.clone()),
            diverged: false,
            generation: 0,
        }),
        project_id: "project".to_string(),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        resume_compaction_offer: None,
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
        cockpit_proto::ActiveModelSwitchTrigger::Quick,
    ));
    control_rx
        .try_recv()
        .expect("generation-one selection request delivered");
    let selection_id = app.pending_model_selection.as_ref().unwrap().selection_id;
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: requested.provider.clone(),
            model: requested.model.clone(),
            reasoning_effort: requested
                .reasoning_effort
                .as_ref()
                .map(|effort| effort.value.clone()),
            thinking_mode: requested.thinking_mode,
            prompt_cache_retention: requested.prompt_cache_retention,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: requested.clone(),
                    default_selection: Some(requested),
                    diverged: false,
                    generation: 1,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::NotRequested,
            },
        },
    );
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
#[test]
fn composer_model_menu_unchanged_verified_default_reports_already_set_without_claiming_a_write() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let (mut app, _control_rx, selection_id) = composer_app_awaiting_default_terminal(&tmp);

    let verified = selection("p", "a");
    let minimum_generation = app
        .pending_model_selection
        .as_ref()
        .map(|pending| pending.minimum_generation)
        .unwrap_or(1)
        .max(1);
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: "p".into(),
            model: "a".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: verified.clone(),
                    default_selection: Some(verified.clone()),
                    diverged: false,
                    generation: minimum_generation,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::Verified {
                    selection: verified,
                    generation: 1,
                    scope_label: "user".into(),
                    unchanged: true,
                },
            },
        },
    );

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
#[test]
fn composer_model_menu_rejected_default_retains_intent_and_states_the_default_did_not_change() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let (mut app, _control_rx, selection_id) = composer_app_awaiting_default_terminal(&tmp);

    app.apply_event(cockpit_client::presentation::TurnEvent::ModelSelectionResult {
        selection_id,
        provider: "p".into(),
        model: "a".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
        outcome: cockpit_proto::ModelSelectionOutcome::Rejected {
            user_message: "Could not make `p/a` the default for new sessions — the highest-precedence config layer (project) is not writable. The default was not changed and this session kept its model."
                .into(),
            diagnostic_code: "effective_default_target_unwritable".into(),
        },
    });

    assert!(
        composer_model_menu_open(&app)
            && composer_menu_error_text(&app)
                .as_deref()
                .is_some_and(|error| {
                    error.contains("The default was not changed") && error.contains("not writable")
                }),
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
