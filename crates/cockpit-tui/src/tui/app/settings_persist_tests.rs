use super::App;
use crate::tui::settings::{Dialog, with_settings_q_fixture};
use cockpit_config::providers::ConfigDoc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use std::path::Path;
use std::time::Duration;

fn press(app: &mut App, code: KeyCode) {
    assert!(!app.handle_key(KeyEvent::new(code, KeyModifiers::NONE)));
}

fn screen(app: &App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, 60)).unwrap();
    let mut links = crate::tui::links::LinkRegistry::default();
    terminal
        .draw(|frame| app.dialog.render(frame, frame.area(), &mut links))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(100)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

fn app_with_dialog(root: &Path, dialog: crate::tui::settings::SettingsDialog) -> App {
    let mut app = App::new(Some(root), false);
    app.lifecycle = crate::tui::settings::test_lifecycle_client();
    app.dialog = Dialog::Settings(Box::new(dialog));
    app
}

fn edit(app: &mut App, provider_scope: bool) {
    press(app, KeyCode::Enter);
    if !provider_scope {
        for ch in "131072".chars() {
            press(app, KeyCode::Char(ch));
        }
        press(app, KeyCode::Enter);
    }
}

async fn drain_to(app: &mut App, done: impl Fn(&App) -> bool) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            app.drain_async_actions();
            app.drain_agent_events();
            if done(app) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("settings save must settle through App effect drain");
}

#[test]
fn settings_q_app_retains_queued_save_until_success_for_both_pages() {
    for provider_scope in [false, true] {
        with_settings_q_fixture(provider_scope, false, |root, runtime, dialog| {
            let path = root.join(".cockpit/config.json");
            let provider_path =
                cockpit_config::providers::provider_file_path_for_config(&path, "lmstudio")
                    .unwrap();
            let before = std::fs::read(&provider_path).unwrap();
            let mut app = app_with_dialog(root, dialog);
            edit(&mut app, provider_scope);
            press(&mut app, KeyCode::Char('q'));
            assert!(app.dialog.is_active(), "q must retain the effect owner");
            assert!(screen(&app).contains("saving provider…"));
            assert_eq!(
                std::fs::read(&provider_path).unwrap(),
                before,
                "no synchronous test flush"
            );
            // Repeated q and Esc cannot drop an unsettled operation.
            press(&mut app, KeyCode::Char('q'));
            press(&mut app, KeyCode::Esc);
            assert!(app.dialog.is_active());
            runtime.block_on(drain_to(&mut app, |app| !app.dialog.is_active()));
            let saved = ConfigDoc::load_effective_from_paths(std::slice::from_ref(&path));
            let provider = &saved.providers["lmstudio"];
            if provider_scope {
                assert_eq!(
                    provider.location,
                    Some(cockpit_config::providers::ModelLocation::Local)
                );
            } else {
                assert_eq!(
                    provider.models[0].capability_overrides.context_tokens,
                    Some(131_072)
                );
            }
        });
    }
}

#[test]
fn settings_q_app_preflight_rejection_retains_draft_and_error_for_both_pages() {
    for provider_scope in [false, true] {
        with_settings_q_fixture(provider_scope, true, |root, runtime, dialog| {
            let path = root.join(".cockpit/config.json");
            let provider_path =
                cockpit_config::providers::provider_file_path_for_config(&path, "lmstudio")
                    .unwrap();
            let before = std::fs::read(&provider_path).unwrap();
            let mut app = app_with_dialog(root, dialog);
            edit(&mut app, provider_scope);
            press(&mut app, KeyCode::Char('q'));
            let text = screen(&app);
            assert!(app.dialog.is_active());
            assert!(text.contains("save failed:"), "{text}");
            assert!(text.contains("no edit capability"), "{text}");
            assert!(
                text.contains(if provider_scope { "local" } else { "131072" }),
                "{text}"
            );
            runtime.block_on(async {
                app.drain_async_actions();
                tokio::task::yield_now().await;
                app.drain_async_actions();
            });
            assert!(app.dialog.is_active());
            assert_eq!(std::fs::read(&provider_path).unwrap(), before);
        });
    }
}

#[test]
fn settings_q_app_daemon_rejection_retains_draft_and_error_for_both_pages() {
    use cockpit_proto::{Request, Response, WorkspaceTrustMode};
    for provider_scope in [false, true] {
        with_settings_q_fixture(provider_scope, false, |root, runtime, dialog| {
            let path = root.join(".cockpit/config.json");
            let provider_path =
                cockpit_config::providers::provider_file_path_for_config(&path, "lmstudio")
                    .unwrap();
            let before = std::fs::read(&provider_path).unwrap();
            let mut app = app_with_dialog(root, dialog);
            edit(&mut app, provider_scope);
            press(&mut app, KeyCode::Char('q'));
            assert!(app.dialog.is_active());
            assert!(screen(&app).contains("saving provider…"));
            // Revoke authority in the actual daemon after enqueue and before
            // App starts the effect. The saved snapshot cannot authorize it.
            runtime.block_on(async {
                let client = crate::tui::settings::settings_daemon_client(&app.lifecycle)
                    .await
                    .unwrap();
                let project_root = root.display().to_string();
                let Response::WorkspaceTrust {
                    config_generation, ..
                } = client
                    .request_ok(Request::GetWorkspaceTrust {
                        project_root: project_root.clone(),
                    })
                    .await
                    .unwrap()
                else {
                    panic!("workspace trust")
                };
                client
                    .request_ok(Request::SetWorkspaceTrust {
                        project_root,
                        mode: WorkspaceTrustMode::Untrusted,
                        expected_config_generation: config_generation,
                    })
                    .await
                    .unwrap();
                drain_to(&mut app, |app| screen(app).contains("save failed:")).await;
            });
            assert!(app.dialog.is_active());
            let text = screen(&app);
            assert!(text.contains("save failed:"), "{text}");
            assert!(
                text.contains(if provider_scope { "local" } else { "131072" }),
                "{text}"
            );
            assert_eq!(std::fs::read(&provider_path).unwrap(), before);
        });
    }
}

#[test]
fn settings_q_app_unchanged_save_closes_immediately_for_both_pages() {
    for provider_scope in [false, true] {
        with_settings_q_fixture(provider_scope, false, |root, _runtime, dialog| {
            let path = root.join(".cockpit/config.json");
            let provider_path =
                cockpit_config::providers::provider_file_path_for_config(&path, "lmstudio")
                    .unwrap();
            let before = std::fs::read(&provider_path).unwrap();
            let mut app = app_with_dialog(root, dialog);
            press(&mut app, KeyCode::Char('q'));
            assert!(
                !app.dialog.is_active(),
                "unchanged save has no work to drop"
            );
            assert_eq!(std::fs::read(&provider_path).unwrap(), before);
        });
    }
}

fn retention_selection() -> cockpit_config::providers::ActiveModelRef {
    cockpit_config::providers::ActiveModelRef {
        provider: "lmstudio".into(),
        model: "lfm2.5-24b-a2b".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    }
}

type Control = crate::tui::agent_runner::ControlRequest;

/// Hold only control delivery; the actual runner, attached daemon client,
/// provider effect drain and terminal event routing remain production code.
fn retention_app(
    root: &Path,
    runtime: &tokio::runtime::Runtime,
    dialog: crate::tui::settings::SettingsDialog,
) -> (
    App,
    tokio::sync::mpsc::Sender<Control>,
    tokio::sync::mpsc::Receiver<Control>,
) {
    let lifecycle = crate::tui::settings::test_lifecycle_client();
    let runner = runtime
        .block_on(crate::tui::agent_runner::try_spawn_with_model(
            root,
            None,
            retention_selection(),
            false,
            lifecycle.clone(),
            cockpit_client::LifecycleIntent::AttachOrPersistent,
        ))
        .expect("real attached settings runner");
    let mut app = App::new(Some(root), false);
    app.lifecycle = lifecycle;
    app.adopt_runner(Ok(runner));
    // Adoption dispatches its startup host-capability control on the real
    // channel. Hold settings controls only after that initialization.
    let (hold_tx, hold_rx) = tokio::sync::mpsc::channel(8);
    let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
    let real_tx = std::mem::replace(&mut runner.control_tx, hold_tx);
    app.dialog = Dialog::Settings(Box::new(dialog));
    (app, real_tx, hold_rx)
}

fn retention_edit(app: &mut App, combined: bool) {
    press(app, KeyCode::Enter);
    assert!(screen(app).contains("extended"));
    if combined {
        let Dialog::Settings(dialog) = &mut app.dialog else {
            panic!("settings");
        };
        dialog.focus_settings_q_context();
        press(app, KeyCode::Enter);
        // Replace the existing 8192 override through the real numeric editor.
        for _ in 0..4 {
            press(app, KeyCode::Backspace);
        }
        for ch in "131072".chars() {
            press(app, KeyCode::Char(ch));
        }
        press(app, KeyCode::Enter);
    }
}

async fn wait_default_control(
    app: &mut App,
    rx: &mut tokio::sync::mpsc::Receiver<Control>,
) -> Control {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            app.drain_async_actions();
            app.drain_agent_events();
            if let Ok(control) = rx.try_recv() {
                return control;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("default control must remain dispatchable after provider settlement")
}

fn default_update_id(control: &Control) -> uuid::Uuid {
    let cockpit_proto::Request::SetDefaultModel {
        default_update_id,
        prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
        ..
    } = &control.request
    else {
        panic!("extended retention request: {:?}", control.request);
    };
    *default_update_id
}

#[test]
fn settings_q_app_retention_fixture_reaps_follow_on_work_before_reentry() {
    for unwind in [false, true] {
        let mut previous_context = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::tui::settings::with_settings_retention_q_fixture(|root, runtime, dialog| {
                let daemon = runtime
                    .block_on(cockpit_core::daemon::boot_test_persistent_daemon())
                    .unwrap();
                previous_context = Some(std::sync::Arc::downgrade(daemon.context().unwrap()));
                let (mut app, _real_tx, _held_rx) = retention_app(root, runtime, dialog);
                // Adoption starts a real inventory read over the attached
                // client. Leave its follow-on work to fixture teardown rather
                // than depending on whether a presentation drain ran first.
                app.request_inventory_refresh(true);
                if unwind {
                    std::panic::panic_any("retention fixture unwind probe");
                }
            });
        }));
        if unwind {
            assert_eq!(
                result.unwrap_err().downcast_ref::<&str>(),
                Some(&"retention fixture unwind probe")
            );
        } else {
            result.unwrap();
        }
        assert!(
            previous_context.unwrap().upgrade().is_none(),
            "fixture must reap the exact daemon and its admitted readers before reentry"
        );
    }
}

#[test]
fn settings_q_app_retention_only_and_combined_wait_for_all_confirmations() {
    use cockpit_client::presentation::TurnEvent;
    use cockpit_proto::DefaultModelStandaloneOutcome;
    for combined in [false, true] {
        crate::tui::settings::with_settings_retention_q_fixture(|root, runtime, dialog| {
            let path = root.join(".cockpit/config.json");
            let provider_path =
                cockpit_config::providers::provider_file_path_for_config(&path, "lmstudio")
                    .unwrap();
            let main_before = std::fs::read(&path).unwrap();
            let provider_before = std::fs::read(&provider_path).unwrap();
            let (mut app, real_tx, mut held_rx) = retention_app(root, runtime, dialog);
            retention_edit(&mut app, combined);
            press(&mut app, KeyCode::Char('q'));
            assert!(app.dialog.is_active(), "q retains the complete save intent");
            assert_eq!(std::fs::read(&path).unwrap(), main_before);
            assert_eq!(std::fs::read(&provider_path).unwrap(), provider_before);
            if combined {
                assert!(
                    held_rx.try_recv().is_err(),
                    "default must wait for provider revision settlement"
                );
                assert!(app.pending_default_model_update_id.is_none());
            }
            runtime.block_on(async {
                let control = wait_default_control(&mut app, &mut held_rx).await;
                let update_id = default_update_id(&control);
                assert_eq!(app.pending_default_model_update_id, Some(update_id));
                assert!(
                    app.dialog.is_active(),
                    "provider success alone cannot close"
                );
                let provider = ConfigDoc::load_effective_from_paths(std::slice::from_ref(&path));
                assert_eq!(
                    provider.providers["lmstudio"].models[0]
                        .capability_overrides
                        .context_tokens,
                    Some(if combined { 131_072 } else { 8192 })
                );
                let mut target = retention_selection();
                target.prompt_cache_retention =
                    Some(cockpit_config::providers::PromptCacheRetention::Extended);
                let applied = |selection| DefaultModelStandaloneOutcome::Applied {
                    selection: Some(selection),
                    generation: 1,
                    authority_revision: "test-stale".into(),
                    scope_label: "project".into(),
                    unchanged: false,
                };
                app.apply_event(TurnEvent::DefaultModelUpdateResult {
                    default_update_id: uuid::Uuid::new_v4(),
                    outcome: applied(target.clone()),
                });
                app.apply_event(TurnEvent::DefaultModelUpdateResult {
                    default_update_id: uuid::Uuid::new_v4(),
                    outcome: DefaultModelStandaloneOutcome::Rejected {
                        user_message: "stale rejection".into(),
                        diagnostic_code: "stale".into(),
                    },
                });
                target.model = "wrong-target".into();
                app.apply_event(TurnEvent::DefaultModelUpdateResult {
                    default_update_id: update_id,
                    outcome: applied(target),
                });
                assert!(app.dialog.is_active());
                assert_eq!(app.pending_default_model_update_id, Some(update_id));
                assert!(!screen(&app).contains("stale rejection"));
                press(&mut app, KeyCode::Char('q'));
                press(&mut app, KeyCode::Esc);
                assert!(app.dialog.is_active());
                assert!(
                    held_rx.try_recv().is_err(),
                    "pending q cannot duplicate the request"
                );
                real_tx.send(control).await.unwrap();

                // Deliver Ack/config events while retaining the real terminal
                // result. Durable bytes and Ack still cannot authorize close.
                let mut terminal = Vec::new();
                let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
                let actual_events = std::mem::replace(
                    &mut runner.events,
                    std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                );
                tokio::time::timeout(Duration::from_secs(20), async {
                    loop {
                        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
                        for event in crate::tui::agent_runner::drain_turn_events(&actual_events) {
                            if matches!(event.event, TurnEvent::DefaultModelUpdateResult { .. }) {
                                terminal.push(event);
                            } else {
                                runner.events.lock().unwrap().push(event);
                            }
                        }
                        app.drain_async_actions();
                        app.drain_agent_events();
                        if !terminal.is_empty() && app.pending_control_requests.is_empty() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("actual daemon terminal result and Ack");
                assert!(app.dialog.is_active(), "Ack must not close the dialog");
                assert_eq!(app.pending_default_model_update_id, Some(update_id));
                let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
                runner.events.lock().unwrap().extend(terminal);
                drain_to(&mut app, |app| !app.dialog.is_active()).await;
            });
            let saved = ConfigDoc::load_effective_from_paths(std::slice::from_ref(&path));
            assert_eq!(
                saved.active_model.unwrap().prompt_cache_retention,
                Some(cockpit_config::providers::PromptCacheRetention::Extended)
            );
            if !combined {
                assert_eq!(std::fs::read(&provider_path).unwrap(), provider_before);
            }
        });
    }
}

#[test]
fn settings_q_app_default_rejection_retains_retention_draft_after_provider_success() {
    for combined in [false, true] {
        crate::tui::settings::with_settings_retention_q_fixture(|root, runtime, dialog| {
            let path = root.join(".cockpit/config.json");
            let (mut app, real_tx, mut held_rx) = retention_app(root, runtime, dialog);
            retention_edit(&mut app, combined);
            press(&mut app, KeyCode::Char('q'));
            assert!(app.dialog.is_active());
            runtime.block_on(async {
                let control = wait_default_control(&mut app, &mut held_rx).await;
                default_update_id(&control);
                assert!(app.dialog.is_active());
                // A real retained-target read failure after provider success.
                std::fs::write(&path, "[").unwrap();
                real_tx.send(control).await.unwrap();
                drain_to(&mut app, |app| {
                    screen(app).contains("default model save failed:")
                })
                .await;
            });
            assert!(app.dialog.is_active());
            let text = screen(&app);
            assert!(text.contains("extended"), "{text}");
            assert!(text.contains("default model save failed:"), "{text}");
            assert!(app.pending_default_model_update_id.is_none());
            assert!(
                app.history.iter().any(|entry| matches!(
                    entry,
                    crate::tui::history::HistoryEntry::Plain { line }
                        if line.starts_with("Default model was not changed — ")
                )),
                "the real daemon must return a terminal Rejected event"
            );
            if combined {
                assert!(text.contains("131072"), "{text}");
            }
        });
    }
}

#[test]
fn settings_q_app_active_retention_empty_intent_closes_immediately() {
    crate::tui::settings::with_settings_retention_q_fixture(|root, _runtime, dialog| {
        let mut app = app_with_dialog(root, dialog);
        press(&mut app, KeyCode::Char('q'));
        assert!(
            !app.dialog.is_active(),
            "supported retention without an edit is still a true no-op"
        );
    });
}

#[test]
fn settings_q_app_retention_non_delivery_retains_error_and_draft() {
    crate::tui::settings::with_settings_retention_q_fixture(|root, _runtime, dialog| {
        let mut app = app_with_dialog(root, dialog);
        retention_edit(&mut app, false);
        press(&mut app, KeyCode::Char('q'));
        assert!(app.dialog.is_active());
        let text = screen(&app);
        assert!(text.contains("extended"), "{text}");
        assert!(text.contains("default model save failed:"), "{text}");
    });
}

#[test]
fn settings_q_app_combined_provider_rejection_never_sends_default_or_closes() {
    use cockpit_proto::{Request, Response, WorkspaceTrustMode};
    crate::tui::settings::with_settings_retention_q_fixture(|root, runtime, dialog| {
        let path = root.join(".cockpit/config.json");
        let provider_path =
            cockpit_config::providers::provider_file_path_for_config(&path, "lmstudio").unwrap();
        let before = std::fs::read(&provider_path).unwrap();
        let (mut app, _real_tx, mut held_rx) = retention_app(root, runtime, dialog);
        retention_edit(&mut app, true);
        press(&mut app, KeyCode::Char('q'));
        assert!(app.dialog.is_active());
        runtime.block_on(async {
            let client = crate::tui::settings::settings_daemon_client(&app.lifecycle)
                .await
                .unwrap();
            let project_root = root.display().to_string();
            let Response::WorkspaceTrust {
                config_generation, ..
            } = client
                .request_ok(Request::GetWorkspaceTrust {
                    project_root: project_root.clone(),
                })
                .await
                .unwrap()
            else {
                panic!("workspace trust");
            };
            client
                .request_ok(Request::SetWorkspaceTrust {
                    project_root,
                    mode: WorkspaceTrustMode::Untrusted,
                    expected_config_generation: config_generation,
                })
                .await
                .unwrap();
            drain_to(&mut app, |app| {
                screen(app).contains("provider save failed:")
            })
            .await;
        });
        assert!(app.dialog.is_active());
        let text = screen(&app);
        assert!(text.contains("extended"), "{text}");
        assert!(text.contains("131072"), "{text}");
        assert!(
            held_rx.try_recv().is_err(),
            "rejected provider plan cancels the unsent default operation"
        );
        assert_eq!(std::fs::read(&provider_path).unwrap(), before);
    });
}

#[test]
fn settings_q_app_retention_failed_control_and_epoch_change_keep_draft() {
    for failure in ["rejected", "transport", "epoch"] {
        crate::tui::settings::with_settings_retention_q_fixture(|root, runtime, dialog| {
            let path = root.join(".cockpit/config.json");
            let before = std::fs::read(&path).unwrap();
            let (mut app, _real_tx, mut held_rx) = retention_app(root, runtime, dialog);
            retention_edit(&mut app, false);
            press(&mut app, KeyCode::Char('q'));
            runtime.block_on(async {
                let control = wait_default_control(&mut app, &mut held_rx).await;
                let update_id = default_update_id(&control);
                if failure == "epoch" {
                    app.abandon_epoch_bound_control_receipts(
                        super::ControlEpochAbandonment::SameSession,
                    );
                    let mut selection = retention_selection();
                    selection.prompt_cache_retention =
                        Some(cockpit_config::providers::PromptCacheRetention::Extended);
                    app.apply_event(
                        cockpit_client::presentation::TurnEvent::DefaultModelUpdateResult {
                            default_update_id: update_id,
                            outcome: cockpit_proto::DefaultModelStandaloneOutcome::Applied {
                                selection: Some(selection),
                                generation: 1,
                                authority_revision: "old-epoch".into(),
                                scope_label: "project".into(),
                                unchanged: false,
                            },
                        },
                    );
                } else {
                    let error = if failure == "rejected" {
                        crate::tui::agent_runner::ControlRequestError::rejected("request refused")
                    } else {
                        crate::tui::agent_runner::ControlRequestError::from(
                            "transport failed".to_string(),
                        )
                    };
                    control.response_tx.send(Err(error)).unwrap();
                    drain_to(&mut app, |app| {
                        screen(app).contains("default model save failed:")
                    })
                    .await;
                }
            });
            assert!(app.dialog.is_active());
            assert!(app.pending_default_model_update_id.is_none());
            let text = screen(&app);
            assert!(text.contains("default model save failed:"), "{text}");
            assert!(text.contains("extended"), "{text}");
            assert_eq!(std::fs::read(&path).unwrap(), before);
        });
    }
}
