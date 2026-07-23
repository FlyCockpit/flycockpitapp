use super::{App, ToastKind};
use cockpit_core::daemon::proto::{
    InterruptOption, InterruptQuestion, InterruptQuestionSet, InterruptRaiseReason,
};
use cockpit_core::engine::TurnEvent;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use uuid::Uuid;

fn app() -> App {
    let tmp = tempfile::tempdir().unwrap();
    App::new(Some(tmp.path()), false)
}

fn question_set(permission: bool) -> InterruptQuestionSet {
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
            permission,
            approval_class: None,
            sandbox_escalation: None,
        }],
    }
}

fn raise(session_id: Uuid, interrupt_id: Uuid, pending_count: usize) -> TurnEvent {
    raise_with_reason(
        session_id,
        interrupt_id,
        pending_count,
        InterruptRaiseReason::Initial,
    )
}

fn raise_with_reason(
    session_id: Uuid,
    interrupt_id: Uuid,
    pending_count: usize,
    reason: InterruptRaiseReason,
) -> TurnEvent {
    TurnEvent::InterruptRaised {
        session_id,
        interrupt_id,
        description: String::new(),
        questions: question_set(false),
        pending_count,
        reason,
    }
}

#[test]
fn foreground_visible_interrupt_opens_dialog_without_persistent_toast() {
    let mut app = app();
    let session_id = Uuid::new_v4();
    app.launch.session_id = Some(session_id);

    app.apply_event(raise(session_id, Uuid::new_v4(), 0));

    assert!(app.question_dialog.is_some());
    assert!(app.attention_interrupt.is_some());
    assert!(
        app.toast.is_none(),
        "visible foreground dialog should not create an action-required toast"
    );
}

#[test]
fn background_interrupt_uses_persistent_toast_without_dialog() {
    let mut app = app();
    let foreground_session = Uuid::new_v4();
    let background_session = Uuid::new_v4();
    app.launch.session_id = Some(foreground_session);

    app.apply_event(raise(background_session, Uuid::new_v4(), 1));

    assert!(app.question_dialog.is_none());
    assert_eq!(app.background_attention_interrupts.len(), 1);
    let toast = app.toast.as_ref().expect("background interrupt toast");
    assert!(toast.persistent);
    assert_eq!(toast.kind, ToastKind::Info);
    assert_eq!(toast.text, "Question waiting");
    assert_eq!(app.attention_waiting_count(), 2);
}

#[test]
fn background_resolve_clears_stale_persistent_toast_while_foreground_remains_visible() {
    let mut app = app();
    let foreground_session = Uuid::new_v4();
    let background_session = Uuid::new_v4();
    let background_interrupt = Uuid::new_v4();
    app.launch.session_id = Some(foreground_session);

    app.apply_event(raise(foreground_session, Uuid::new_v4(), 0));
    app.apply_event(raise(background_session, background_interrupt, 0));
    assert!(app.toast.as_ref().is_some_and(|toast| toast.persistent));

    app.apply_event(TurnEvent::InterruptResolved {
        session_id: background_session,
        interrupt_id: background_interrupt,
    });

    assert!(app.question_dialog.is_some());
    assert!(app.attention_interrupt.is_some());
    assert!(app.background_attention_interrupts.is_empty());
    assert!(
        app.toast.is_none(),
        "background toast clears once only a visible foreground dialog remains"
    );
}

#[test]
fn dialog_ux_lockout_only_first_of_chain() {
    for (reason, expected_locked) in [
        (InterruptRaiseReason::Initial, true),
        (InterruptRaiseReason::Advance, false),
        (InterruptRaiseReason::Rehydration, true),
    ] {
        let mut app = app();
        let session_id = Uuid::new_v4();
        let interrupt_id = Uuid::new_v4();
        app.launch.session_id = Some(session_id);
        app.composer_active_since_dialog = true;

        app.apply_event(raise_with_reason(session_id, interrupt_id, 1, reason));

        let dialog = app.question_dialog.as_mut().expect("dialog");
        assert_eq!(dialog.interrupt_id(), interrupt_id);
        assert_eq!(dialog.pending_count(), 1);
        assert_eq!(dialog.locked(), expected_locked, "{reason:?}");
        if expected_locked {
            assert!(!dialog.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
            assert!(
                dialog.take_result().is_none(),
                "Esc during lockout must not cancel {reason:?}"
            );
        } else {
            assert!(dialog.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
            assert!(
                matches!(
                    dialog.take_result(),
                    Some(crate::tui::dialog::question::QuestionResult::Cancel { .. })
                ),
                "Esc should cancel immediately interactive {reason:?}"
            );
        }
    }
}

#[test]
fn repeated_raise_for_active_interrupt_updates_counter_without_takeover() {
    let mut app = app();
    let session_id = Uuid::new_v4();
    let interrupt_id = Uuid::new_v4();
    app.launch.session_id = Some(session_id);

    app.apply_event(raise(session_id, interrupt_id, 0));
    let dialog = app.question_dialog.as_ref().expect("initial dialog");
    assert_eq!(dialog.interrupt_id(), interrupt_id);
    assert!(!dialog.is_approval());

    app.apply_event(TurnEvent::InterruptRaised {
        session_id,
        interrupt_id,
        description: "new payload should not replace the active dialog".to_string(),
        questions: question_set(true),
        pending_count: 3,
        reason: InterruptRaiseReason::Rehydration,
    });

    let dialog = app.question_dialog.as_ref().expect("same active dialog");
    assert_eq!(dialog.interrupt_id(), interrupt_id);
    assert_eq!(dialog.pending_count(), 3);
    assert!(
        !dialog.is_approval(),
        "same-id re-raise should update queue metadata without replacing the visible dialog"
    );
    assert_eq!(
        app.attention_interrupt
            .as_ref()
            .map(|state| state.pending_count),
        Some(3)
    );
}
