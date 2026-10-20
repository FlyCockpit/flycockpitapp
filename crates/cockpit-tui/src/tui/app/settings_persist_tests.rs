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
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
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
