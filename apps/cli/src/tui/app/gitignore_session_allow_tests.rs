use super::App;
use crate::engine::TurnEvent;
use crate::tui::settings::Dialog;
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

fn at_popup_app(tmp: &tempfile::TempDir) -> App {
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = Dialog::None;
    let cwd = app.launch.cwd.clone();
    fs::create_dir(cwd.join(".git")).unwrap();
    fs::write(cwd.join("kept.rs"), "").unwrap();
    app
}

/// The daemon's `GitignoreAllow` push overwrites the tracked session set
/// wholesale (full-list replace) and drops the `@`-suggestion memo so the
/// next popup render re-walks with the new globs — purely client-side, no
/// transcript entry (implementation note).
#[test]
fn apply_replaces_field_and_invalidates_at_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let history_len_before = app.history.len();

    // Empty by default — nothing approved yet.
    assert!(app.gitignore_session_allow.is_empty());

    // Seed a memo entry so we can prove the apply-handler invalidates it.
    *app.at_cache.borrow_mut() = Some(("q".to_string(), Vec::new()));

    app.apply_event(TurnEvent::GitignoreAllow {
        allow: vec!["target/".to_string(), "secret.txt".to_string()],
    });
    assert_eq!(
        app.gitignore_session_allow,
        vec!["target/".to_string(), "secret.txt".to_string()],
    );
    // Cache dropped → the next `at_suggestions` re-walks with the new set.
    assert!(app.at_cache.borrow().is_none());
    // A later push replaces the set wholesale (not a delta merge).
    app.apply_event(TurnEvent::GitignoreAllow {
        allow: vec!["build/".to_string()],
    });
    assert_eq!(app.gitignore_session_allow, vec!["build/".to_string()]);
    // Purely client-side: nothing entered the transcript.
    assert_eq!(app.history.len(), history_len_before);
}

/// The popup's effective allow list is the union of the persisted per-layer
/// config and the daemon-pushed session set. A gitignored file invisible
/// with no session approval is re-included (dimmed, `gitignored`) once the
/// session set carries its glob — exercised through the real `at_suggestions`
/// render path, including the cache invalidation on the apply-handler.
#[test]
fn at_suggestions_unions_session_allow_with_persisted() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    // Build the cwd into a git worktree with a gitignored file.
    let cwd = app.launch.cwd.clone();
    fs::create_dir(cwd.join(".git")).unwrap();
    fs::write(cwd.join(".gitignore"), "secret.txt\n").unwrap();
    fs::write(cwd.join("kept.rs"), "").unwrap();
    fs::write(cwd.join("secret.txt"), "").unwrap();

    // Activate the `@`-popup query (bare `@` → empty partial → whole tree).
    app.composer.insert_str("@");
    assert_eq!(app.composer.at_query(), Some(""));

    // No session approval → the gitignored file is absent from the popup.
    let before = app.at_suggestions();
    assert!(
        !before.iter().any(|s| s.display == "secret.txt"),
        "gitignored file hidden without an approval"
    );
    // The tracked file is present (sanity that the walk found the cwd).
    assert!(before.iter().any(|s| s.display == "kept.rs"));

    // The daemon pushes the session approval → re-included, dimmed.
    app.apply_event(TurnEvent::GitignoreAllow {
        allow: vec!["secret.txt".to_string()],
    });
    let after = app.at_suggestions();
    let entry = after
        .iter()
        .find(|s| s.display == "secret.txt")
        .expect("session-approved gitignored file surfaces in the popup");
    assert!(
        entry.gitignored,
        "session-re-included entry flagged gitignored (dimmed) like a persisted one"
    );
}

#[test]
fn at_popup_no_match_enter_dismisses_not_submits() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = at_popup_app(&tmp);
    app.at_selected = 7;
    app.at_scroll = 3;
    app.composer.insert_str("@zzz-no-such-file");

    assert!(app.at_suggestions().is_empty());
    assert!(app.at_popup_active());

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert!(!app.at_popup_active());
    assert!(app.at_dismissed);
    assert_eq!(app.composer.text(), "@zzz-no-such-file");
    assert_eq!(app.at_selected, 0);
    assert_eq!(app.at_scroll, 0);
}

#[test]
fn at_popup_match_enter_still_accepts() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = at_popup_app(&tmp);
    app.composer.insert_str("@kept");

    assert_eq!(app.at_suggestions().len(), 1);
    assert!(app.at_popup_active());

    let exit = app.handle_key(press(KeyCode::Enter));

    assert!(!exit);
    assert_eq!(app.composer.text(), "@kept.rs ");
    assert!(!app.at_popup_active());
    assert!(app.at_dismissed);
    assert_eq!(app.at_selected, 0);
    assert_eq!(app.at_scroll, 0);
}

#[test]
fn at_popup_no_match_second_enter_submits() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = at_popup_app(&tmp);
    app.composer.insert_str("@zzz-no-such-file");

    assert!(!app.handle_key(press(KeyCode::Enter)));
    assert_eq!(app.composer.text(), "@zzz-no-such-file");
    assert!(app.at_dismissed);

    assert!(!app.handle_key(press(KeyCode::Enter)));
    assert_eq!(app.composer.text(), "");
    assert!(!app.at_dismissed);
}

#[test]
fn at_popup_tab_and_enter_agree_on_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = at_popup_app(&tmp);
    app.composer.insert_str("@zzz-no-such-file");

    assert!(app.at_suggestions().is_empty());
    assert!(!app.handle_key(press(KeyCode::Tab)));
    assert_eq!(app.composer.text(), "@zzz-no-such-file");
    assert!(app.at_popup_active());

    app.composer.set("@zzz-no-such-file");
    app.refresh_at_dismiss();
    assert!(app.at_popup_active());
    assert!(!app.handle_key(press(KeyCode::Enter)));
    assert_eq!(app.composer.text(), "@zzz-no-such-file");
    assert!(!app.at_popup_active());
}
