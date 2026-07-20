use super::{App, HistoryEntry};
use crate::tui::settings::Dialog;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

fn ctrl(ch: char) -> KeyEvent {
    KeyEvent {
        code: KeyCode::Char(ch),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn agent(reasoning: &str, expanded: bool) -> HistoryEntry {
    HistoryEntry::Agent {
        name: "agent".to_string(),
        text: "answer".to_string(),
        reasoning: reasoning.to_string(),
        timestamp: chrono::Local::now(),
        expanded,
        reasoning_offset: 0,
        think_duration: None,
        seq: None,
    }
}

fn reasoning_expanded(entry: &HistoryEntry) -> bool {
    match entry {
        HistoryEntry::Agent { expanded, .. } => *expanded,
        _ => panic!("expected agent entry"),
    }
}

fn plain_app(tmp: &tempfile::TempDir) -> App {
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = Dialog::None;
    app.composer.set_vim_enabled(false);
    app
}

#[test]
fn ctrl_t_toggles_all_reasoning_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = plain_app(&tmp);
    app.history.push(agent("first thought", false));
    app.history.push(agent("second thought", true));

    app.handle_key(ctrl('t'));

    assert!(app.history.iter().all(reasoning_expanded));

    app.handle_key(ctrl('t'));

    assert!(app.history.iter().all(|entry| !reasoning_expanded(entry)));
}

#[test]
fn ctrl_j_inserts_newline_even_when_reasoning_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = plain_app(&tmp);
    app.history.push(agent("hidden thought", false));
    app.composer.set("line one".to_string());

    app.handle_key(ctrl('j'));

    assert_eq!(app.composer.text(), "line one\n");
    assert!(!reasoning_expanded(&app.history[0]));
}

#[test]
fn ctrl_t_without_reasoning_does_not_mutate_composer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = plain_app(&tmp);
    app.composer.set("unchanged".to_string());

    app.handle_key(ctrl('t'));

    assert_eq!(app.composer.text(), "unchanged");
    assert!(app.history.is_empty());
}
