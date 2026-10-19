use super::*;
use crate::tui::agent_runner::TestRunnerOverrides;
use crate::tui::structured_paste;
use cockpit_proto::Request;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[test]
fn composer_insert_default_and_settings_vim_opt_in() {
    let mut app = App::new(None, false);
    assert_eq!(
        cockpit_config::extended::VimModeSetting::default(),
        cockpit_config::extended::VimModeSetting::Disabled
    );
    app.apply_tui_config_from_snapshot();
    assert!(!app.composer.vim_enabled());
    assert_eq!(app.composer.vim_mode(), VimMode::Insert);
    app.handle_key_insert(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    app.handle_key_insert(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.composer.text(), "j");
    assert_eq!(app.composer.vim_mode(), VimMode::Insert);

    app.config_snapshot.extended.tui.vim_mode = cockpit_config::extended::VimModeSetting::Hint;
    app.apply_tui_config_from_snapshot();
    assert!(app.composer.vim_enabled());
    app.busy = true;
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::test_fixture(TestRunnerOverrides {
        control_tx: Some(tx),
        ..Default::default()
    })));
    app.handle_key_insert(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.composer.vim_mode(), VimMode::Normal);
    assert!(
        rx.try_recv().is_err(),
        "vim Esc changes mode without stopping the turn"
    );
    assert_eq!(app.composer.text(), "j");

    app.config_snapshot.extended.tui.vim_mode = cockpit_config::extended::VimModeSetting::Disabled;
    app.apply_tui_config_from_snapshot();
    app.handle_key_insert(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.composer.vim_mode(), VimMode::Insert);
    assert!(matches!(
        rx.try_recv().unwrap().request,
        Request::CancelTurn
    ));
    assert_eq!(app.composer.text(), "j");
    assert!(!app.exit_requested);
}

#[test]
fn composer_plain_escape_stops_active_turn_with_palette() {
    let mut app = App::new(None, false);
    app.composer.set_vim_enabled(false);
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::test_fixture(TestRunnerOverrides {
        control_tx: Some(tx),
        ..Default::default()
    })));
    app.busy = true;
    app.composer.set("/q".to_string());
    assert!(!app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
    assert!(matches!(
        rx.try_recv().unwrap().request,
        Request::CancelTurn
    ));
    assert_eq!(app.composer.vim_mode(), VimMode::Insert);
    assert_eq!(app.composer.text(), "/q");
}

#[test]
fn composer_unknown_slash_feedback_retains_and_can_send_text() {
    for text in [
        "/hlep",
        "/no-such-command arg",
        "/ quit",
        "/ rename Title",
        "/\nquit",
    ] {
        let mut app = App::new(None, false);
        seed_ready_model_for_tests(&mut app);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        app.agent_runner = Some(Ok(AgentRunner::test_fixture(TestRunnerOverrides {
            input_tx: Some(tx),
            ..Default::default()
        })));
        app.composer.set(text.to_string());
        assert!(!app.complete_or_submit());
        assert_eq!(app.composer.text(), text);
        let notice = &app.toast.as_ref().expect("unknown command feedback").text;
        assert!(notice.contains("Unknown slash command") && notice.contains("/help"));
        assert!(rx.try_recv().is_err(), "first Enter is feedback only");
        assert!(!app.complete_or_submit());
        let input = rx
            .try_recv()
            .expect("second Enter sends the preserved text");
        assert_eq!(input.text, text);
        assert!(app.composer.is_empty());
        assert!(!app.dialog.is_active());
    }
}

#[test]
fn composer_argument_slash_runs_without_model_and_keeps_workspace_guard() {
    let mut app = App::new(None, false);
    assert!(app.config_snapshot.providers.providers.is_empty());
    app.composer.set("/rename Title".to_string());
    assert!(!app.complete_or_submit());
    assert!(app.composer.is_empty());
    assert!(
        !app.dialog.is_active(),
        "rename must never open provider setup"
    );
    assert!(app.history.iter().any(|entry| matches!(entry,
        HistoryEntry::Plain { line } if line.contains("/rename: no active session"))));

    app.startup_background.started = true;
    app.startup_background.workspace_ready = false;
    app.composer.set("/rename Private".to_string());
    assert!(!app.complete_or_submit());
    assert_eq!(app.composer.text(), "/rename Private");
    assert!(
        app.toast
            .as_ref()
            .unwrap()
            .text
            .contains("accepts the workspace")
    );
}

#[test]
fn composer_quit_and_exit_share_the_authority_fence() {
    for command in ["/quit", "/exit", "/quit "] {
        let mut app = App::new(None, false);
        app.composer.set(command.to_string());
        assert!(
            app.complete_or_submit(),
            "idle {command} exits without a model"
        );
        app.pending_prune_confirm = true;
        app.composer.set(command.to_string());
        assert!(
            !app.complete_or_submit(),
            "{command} cannot abandon authority"
        );
        assert!(app.pending_prune_confirm);
        assert!(
            app.toast
                .as_ref()
                .unwrap()
                .text
                .contains("verified terminal state")
        );
    }
}

#[test]
fn composer_bracketed_paste_preserves_whitespace_and_tab_geometry() {
    for source in [
        structured_paste::PasteSource::BracketedPty,
        structured_paste::PasteSource::NativePaste,
    ] {
        for (payload, expected) in [
            ("def item():\n\treturn 1", "def item():\n\treturn 1"),
            ("def item():\r\treturn 1", "def item():\n\treturn 1"),
            ("def item():\r\n\treturn 1", "def item():\n\treturn 1"),
        ] {
            let mut app = App::new(None, false);
            app.handle_observed_terminal_event(
                Event::Paste(payload.into()),
                Duration::ZERO,
                1,
                Some(source),
                Some(uuid::Uuid::new_v4()),
            );
            assert_eq!(app.composer.text(), expected);
            assert_eq!(app.composer.display_text(), expected);
            assert_eq!(app.composer.wire_parts(true).0, expected);
            assert_eq!(crate::tui::composer::display_width("\treturn 1"), 12);
        }
    }
    let mut app = App::new(None, false);
    let payload = "def item():\n\treturn 1\n".repeat(10);
    app.handle_paste(payload.replace('\n', "\r"));
    assert!(app.composer.display_text().contains(&payload));
    assert!(app.composer.wire_parts(true).0.contains(&payload));
    app.handle_paste(payload.clone());
    assert_eq!(
        app.composer.text(),
        payload,
        "repaste expands the exact normalized payload"
    );
}

#[tokio::test]
async fn composer_quit_reaps_repository_projection_lifecycle_owners() {
    for graceful in [true, false] {
        let (lifecycle, mut requests) = cockpit_client::LifecycleClient::channel(8);
        let mut app = App::new(None, false);
        app.lifecycle = lifecycle.clone();
        app.background_projections.0.push(spawn_git_refresh(
            app.launch.cwd.clone(),
            lifecycle.clone(),
            Arc::clone(&app.repo_status),
        ));
        app.background_projections
            .0
            .push(spawn_worktree_root_resolve(
                app.launch.cwd.clone(),
                lifecycle,
                Arc::clone(&app.worktree_root),
            ));
        let first = tokio::time::timeout(Duration::from_secs(1), requests.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(1), requests.recv())
            .await
            .unwrap()
            .unwrap();
        if graceful {
            tokio::time::timeout(
                Duration::from_millis(250),
                app.background_projections.shutdown(),
            )
            .await
            .expect("read-only pollers cancel promptly");
        }
        drop(app);
        assert!(
            tokio::time::timeout(Duration::from_millis(250), requests.recv())
                .await
                .unwrap()
                .is_none(),
            "graceful={graceful}: no detached poller may keep the CLI lifecycle actor alive"
        );
        assert!(
            first.reply.is_closed() && second.reply.is_closed(),
            "both projection futures retired"
        );
    }
}
