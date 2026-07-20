use super::{App, HistoryEntry, Overlay, SLASH_COMMANDS, SideConversation, input};
use crate::tui::async_action::AsyncActionKind;
use crate::tui::keys_overlay::KeyContext;
use cockpit_core::daemon::proto::{
    InterruptOption, InterruptQuestion, InterruptQuestionSet, SessionSummary,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use std::fs;
use std::time::Duration;
use uuid::Uuid;

fn ctrl(ch: char) -> KeyEvent {
    KeyEvent {
        code: KeyCode::Char(ch),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
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

fn configured_app(tmp: &tempfile::TempDir) -> App {
    let _env = cockpit_config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    fs::write(cockpit.join("config.json"), "{}").unwrap();
    let provider_dir = cockpit.join("providers");
    fs::create_dir(&provider_dir).unwrap();
    fs::write(
        provider_dir.join("p.json"),
        r#"{"url":"https://example.test","models":[{"id":"m"}]}"#,
    )
    .unwrap();
    App::new(Some(tmp.path()), false)
}

fn session_summary(session_id: Uuid, project_root: String) -> SessionSummary {
    SessionSummary {
        session_id,
        short_id: Some("abcdef".to_string()),
        project_root,
        project_id: "pid".to_string(),
        started_at: 1,
        last_active_at: 2,
        turns: 1,
        active_agent: "Build".to_string(),
        title: Some("summary".to_string()),
        parent_session_id: None,
        created_by_principal: None,
        shared_with_collaborators: false,
        fork_count: 0,
        descendant_count: 0,
        last_viewed_at: None,
        latest_activity_at: None,
        open_interrupts: 0,
        activity_state: None,
        archived_at: None,
        pin_count: 0,
    }
}

fn fake_side_conversation(tmp: &std::path::Path) -> SideConversation {
    SideConversation {
        side_session_id: Uuid::new_v4(),
        socket: tmp.join("missing-daemon.sock"),
        saved_runner: None,
        saved_history: vec![HistoryEntry::Plain {
            line: "main history".to_string(),
        }],
        saved_queue: vec![input::optimistic_queue_item(
            "queued main message".to_string(),
        )],
        saved_pending: None,
        saved_prunable_tokens: 42,
        saved_cache_cold: false,
        saved_elided_event_ids: std::collections::HashSet::from(["event-1".to_string()]),
        saved_active_schedules: std::collections::BTreeMap::new(),
        saved_pending_stop_confirm: Some(vec!["stop-me".to_string()]),
        saved_chat_scroll_offset: 7,
        saved_project_id: Some("project-main".to_string()),
        saved_session_id: Some(Uuid::new_v4()),
        saved_session_short_id: Some("main123".to_string()),
        saved_current_session_persisted: true,
    }
}

fn single_question_dialog() -> crate::tui::dialog::question::QuestionDialog {
    crate::tui::dialog::question::QuestionDialog::new(
        Uuid::new_v4(),
        String::new(),
        InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Proceed?".to_string(),
                options: vec![
                    InterruptOption {
                        id: "yes".to_string(),
                        label: "Yes".to_string(),
                        description: None,
                        secondary: false,
                    },
                    InterruptOption {
                        id: "no".to_string(),
                        label: "No".to_string(),
                        description: None,
                        secondary: false,
                    },
                ],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        },
        Duration::ZERO,
    )
}

fn app_with_sessions_preview_pane(tmp: &tempfile::TempDir) -> App {
    let mut app = configured_app(tmp);
    let dead_socket = tmp.path().join("no-daemon.sock");
    app.daemon_prompt = None;
    app.daemon_connected = true;
    app.startup_background.daemon_socket = Some(dead_socket.clone());
    let session_id = Uuid::new_v4();
    let mut pane =
        crate::tui::sessions_pane::SessionsPane::open(&app.launch.cwd, true, Some(dead_socket));
    pane.apply_sessions_result(Ok(vec![session_summary(
        session_id,
        app.launch.cwd.display().to_string(),
    )]));
    app.overlay = Overlay::Sessions(pane);
    app
}

async fn drain_async_actions_until_idle(app: &mut App) {
    for _ in 0..100 {
        app.drain_async_actions();
        if app.async_actions.pending_count() == 0 {
            app.drain_async_actions();
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("async actions did not finish");
}

#[test]
fn question_dialog_shadows_and_resumes_an_open_overlay() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.overlay = Overlay::Sessions(crate::tui::sessions_pane::SessionsPane::open(
        &app.launch.cwd,
        false,
        None,
    ));

    assert_eq!(app.key_context(), KeyContext::Sessions);
    app.question_dialog = Some(single_question_dialog());
    assert_eq!(app.key_context(), KeyContext::QuestionDialog);

    app.question_dialog = None;
    assert_eq!(app.key_context(), KeyContext::Sessions);
    assert!(matches!(app.overlay, Overlay::Sessions(_)));
}

#[test]
fn sessions_preview_action_enqueued_on_split_render() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_with_sessions_preview_pane(&tmp);
    assert_eq!(app.async_actions.pending_count(), 0);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert_eq!(
        app.async_actions.pending_kinds(),
        vec![AsyncActionKind::DaemonRpc("sessions.preview")]
    );
    let pending_ids = app.async_actions.pending_ids();
    assert_eq!(pending_ids.len(), 1);

    terminal.draw(|frame| app.render(frame)).unwrap();
    assert_eq!(
        app.async_actions.pending_kinds(),
        vec![AsyncActionKind::DaemonRpc("sessions.preview")]
    );
    assert_eq!(app.async_actions.pending_ids(), pending_ids);
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_preview_rpc_failure_sets_preview_error() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_with_sessions_preview_pane(&tmp);

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    drain_async_actions_until_idle(&mut app).await;

    let Overlay::Sessions(pane) = &app.overlay else {
        panic!("sessions pane should still be open");
    };
    let error = pane
        .preview_error()
        .expect("failed preview RPC should set a preview error");
    assert!(
        error.contains("daemon connect"),
        "unexpected preview error: {error}"
    );
}

/// The leader (`Ctrl+K`) in the main chat opens the overlay in the
/// composer context; pressing it again closes it (toggle), focus unchanged.
#[test]
fn leader_in_main_chat_opens_composer_context_and_toggles_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    assert!(app.keys_overlay.is_none());
    app.handle_key(ctrl('k'));
    let overlay = app.keys_overlay.as_ref().expect("leader opens the overlay");
    assert_eq!(overlay.context(), KeyContext::Composer);

    // Leader again closes it.
    app.handle_key(ctrl('k'));
    assert!(
        app.keys_overlay.is_none(),
        "leader again closes the overlay"
    );

    // Composer text is untouched (overlay is informational, focus unchanged).
    assert!(
        app.composer.text().is_empty(),
        "no key leaked into the composer"
    );
}

/// Opening a pane (`/sessions`) makes the leader show that context first.
#[test]
fn leader_with_sessions_pane_open_shows_sessions_context() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.overlay = Overlay::Sessions(crate::tui::sessions_pane::SessionsPane::open(
        &app.launch.cwd,
        false,
        None,
    ));
    app.handle_key(ctrl('k'));
    let overlay = app.keys_overlay.as_ref().expect("leader opens over a pane");
    assert_eq!(overlay.context(), KeyContext::Sessions);
    // The pane stays open underneath (the overlay is on top, not a swap).
    assert!(matches!(app.overlay, Overlay::Sessions(_)));
}

#[test]
fn leader_with_diff_pane_open_shows_diff_context() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.overlay = Overlay::Diff(crate::tui::diff_pane::DiffPane::open(
        crate::tui::diff_pane::DiffSource::Last,
        tmp.path(),
        &[],
        cockpit_config::extended::DiffStyle::Inline,
    ));

    app.handle_key(ctrl('k'));

    let overlay = app.keys_overlay.as_ref().expect("leader opens over diff");
    assert_eq!(overlay.context(), KeyContext::Diff);
    assert!(matches!(app.overlay, Overlay::Diff(_)));
}

/// While a slash query is typed, the leader shows the slash-menu context.
#[test]
fn leader_with_slash_query_shows_slash_menu_context() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.composer.set("/se");
    assert!(app.slash_query().is_some());
    app.handle_key(ctrl('k'));
    assert_eq!(
        app.keys_overlay.as_ref().unwrap().context(),
        KeyContext::SlashMenu
    );
}

/// Required agent-decision dialogs keep precedence: the leader is consumed
/// by the dialog path and does not obscure the prompt.
#[test]
fn leader_does_not_open_over_question_dialog() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.question_dialog = Some(single_question_dialog());

    app.handle_key(ctrl('k'));

    assert!(
        app.keys_overlay.is_none(),
        "leader must not obscure a required question dialog"
    );
    assert!(
        app.question_dialog.is_some(),
        "the question dialog remains active"
    );
    assert!(
        app.composer.text().is_empty(),
        "no key leaked into the composer"
    );
}

#[test]
fn orphan_tool_end_renders_standalone_success_line() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.apply_event(cockpit_core::engine::agent::TurnEvent::ToolEnd {
        agent: "Build".into(),
        call_id: "orphan-call".into(),
        tool: "read".into(),
        output: "orphan result\nsecond line".into(),
        truncated: false,
        seq: None,
        hint: None,
    });

    assert!(matches!(
        app.history.last(),
        Some(HistoryEntry::ToolLine { call_id, summary, state, .. })
            if call_id == "orphan-call"
                && summary == "orphan result"
                && *state == crate::tui::history::ToolCallState::Success
    ));
}

#[test]
fn read_and_readlock_tool_end_store_captured_output_but_unlock_does_not() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    for (call_id, tool, path, output) in [
        ("read-call", "read", "src/main.rs", "1|fn main() {}"),
        (
            "readlock-call",
            "readlock",
            "src/lib.rs",
            "1|pub fn lib() {}",
        ),
        ("unlock-call", "unlock", "src/lib.rs", "SHOULD_NOT_STORE"),
    ] {
        app.apply_event(cockpit_core::engine::agent::TurnEvent::ToolStart {
            agent: "Build".into(),
            call_id: call_id.into(),
            tool: tool.into(),
            args: serde_json::json!({ "path": path }),
        });
        app.apply_event(cockpit_core::engine::agent::TurnEvent::ToolEnd {
            agent: "Build".into(),
            call_id: call_id.into(),
            tool: tool.into(),
            output: output.into(),
            truncated: false,
            seq: None,
            hint: None,
        });
    }

    let Some(HistoryEntry::ToolBox { calls, .. }) = app.history.last() else {
        panic!("expected tool box");
    };
    let read = calls
        .iter()
        .find(|call| call.call_id == "read-call")
        .unwrap();
    let readlock = calls
        .iter()
        .find(|call| call.call_id == "readlock-call")
        .unwrap();
    let unlock = calls
        .iter()
        .find(|call| call.call_id == "unlock-call")
        .unwrap();

    assert_eq!(read.output, "1|fn main() {}");
    assert_eq!(readlock.output, "1|pub fn lib() {}");
    assert!(unlock.output.is_empty());
}

/// Esc and `q` close the overlay while it is open.
#[test]
fn esc_and_q_close_the_open_overlay() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.toggle_keys_overlay();
    assert!(app.keys_overlay.is_some());
    app.handle_key(press(KeyCode::Esc));
    assert!(app.keys_overlay.is_none(), "Esc closes the overlay");

    app.toggle_keys_overlay();
    app.handle_key(press(KeyCode::Char('q')));
    assert!(app.keys_overlay.is_none(), "q closes the overlay");
}

#[test]
fn side_entry_banner_names_side_end_without_esc_shortcut() {
    let banner = App::side_entry_banner("abc123");
    assert!(banner.contains("abc123"));
    assert!(banner.contains("/side end"));
    assert!(banner.contains("discard"));
    assert!(!banner.contains("Esc"));
    assert!(!banner.contains("empty line"));
}

#[test]
fn esc_on_empty_composer_in_side_conversation_is_non_destructive() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.side_conversation = Some(fake_side_conversation(tmp.path()));
    app.current_session_persisted = false;

    app.handle_key(press(KeyCode::Esc));

    assert!(
        app.side_conversation.is_some(),
        "Esc must not discard the side conversation"
    );
    assert!(
        !app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("Side conversation discarded")
        )),
        "Esc must not announce discard"
    );
    assert!(!app.current_session_persisted);
}

#[tokio::test]
async fn side_end_restores_main_session_snapshot_and_discards_side_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let side = fake_side_conversation(tmp.path());
    let saved_session_id = side.saved_session_id;
    app.side_conversation = Some(side);
    app.current_session_persisted = false;
    app.history.push(HistoryEntry::Plain {
        line: "side-only history".to_string(),
    });

    app.handle_side_command("end");

    assert!(app.side_conversation.is_none());
    assert_eq!(
        app.queue
            .iter()
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>(),
        vec!["queued main message"]
    );
    assert_eq!(app.prunable_tokens, 42);
    assert!(!app.cache_cold);
    assert_eq!(app.chat_scroll_offset, 7);
    assert_eq!(app.project_id.as_deref(), Some("project-main"));
    assert_eq!(app.launch.session_id, saved_session_id);
    assert_eq!(app.launch.session_short_id.as_deref(), Some("main123"));
    assert!(app.current_session_persisted);
    assert!(matches!(
        app.history.last(),
        Some(HistoryEntry::Plain { line }) if line == "Side conversation discarded — back in the main session."
    ));
    assert_eq!(app.async_actions.pending_count(), 1);
}

/// `/keys` opens the overlay; `/keys` and the hidden `/keybindings` alias
/// both resolve to the same registered command.
#[test]
fn keys_slash_command_opens_overlay_and_alias_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    let keys = SLASH_COMMANDS.iter().find(|c| c.name == "keys").unwrap();
    app.composer.set("/keys");
    app.execute_slash(*keys);
    assert!(app.keys_overlay.is_some(), "/keys opens the overlay");

    // The hidden /keybindings alias resolves to the visible /keys command.
    assert_eq!(
        super::hidden_slash_alias("keybindings").unwrap().name,
        "keys"
    );
}

/// `/keys` is registered (visible); `/keybindings` is a hidden alias and is
/// NOT a separate menu entry.
#[test]
fn keys_registered_keybindings_is_a_hidden_alias() {
    assert!(SLASH_COMMANDS.iter().any(|c| c.name == "keys"));
    assert!(
        !SLASH_COMMANDS.iter().any(|c| c.name == "keybindings"),
        "/keybindings is a hidden alias, not a visible command"
    );
}
