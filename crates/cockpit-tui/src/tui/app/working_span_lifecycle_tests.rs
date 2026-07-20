use super::{App, WorkingSpanState};
use cockpit_core::engine::{IdleReason, TurnEvent};

fn app() -> App {
    let tmp = tempfile::tempdir().unwrap();
    App::new(Some(tmp.path()), false)
}

#[test]
fn stale_idle_before_start_does_not_complete_pending_span() {
    let mut app = app();
    app.begin_working_span();
    let turn = app.prediction_state.turn();

    app.apply_event(TurnEvent::AgentIdle {
        turn_id: None,
        reason: IdleReason::Completed,
    });

    assert!(app.busy);
    assert!(app.span_started_at.is_some());
    assert_eq!(app.working_span_state, WorkingSpanState::PendingStart);
    assert_eq!(app.prediction_state.turn(), turn);
}

#[test]
fn matching_start_and_finish_complete_span() {
    let mut app = app();
    app.begin_working_span();
    let turn = app.prediction_state.turn();

    app.apply_event(TurnEvent::ThinkingStarted {
        agent: "Build".to_string(),
        turn_id: Some("turn-1".to_string()),
    });
    assert_eq!(
        app.working_span_state,
        WorkingSpanState::Running {
            turn_id: Some("turn-1".to_string())
        }
    );

    app.apply_event(TurnEvent::AgentIdle {
        turn_id: Some("turn-1".to_string()),
        reason: IdleReason::Completed,
    });

    assert!(!app.busy);
    assert!(app.span_started_at.is_none());
    assert_eq!(app.working_span_state, WorkingSpanState::Idle);
    assert_eq!(app.prediction_state.turn(), turn + 1);
}

#[test]
fn legacy_unidentified_start_and_finish_complete_span() {
    let mut app = app();
    app.begin_working_span();

    app.apply_event(TurnEvent::ThinkingStarted {
        agent: "Build".to_string(),
        turn_id: None,
    });
    app.apply_event(TurnEvent::AgentIdle {
        turn_id: None,
        reason: IdleReason::Completed,
    });

    assert!(!app.busy);
    assert_eq!(app.working_span_state, WorkingSpanState::Idle);
}

#[test]
fn thinking_start_without_local_submit_attaches_to_running_span() {
    let mut app = app();

    app.apply_event(TurnEvent::ThinkingStarted {
        agent: "Build".to_string(),
        turn_id: Some("attached".to_string()),
    });

    assert!(app.busy);
    assert!(app.span_started_at.is_some());
    assert_eq!(
        app.working_span_state,
        WorkingSpanState::Running {
            turn_id: Some("attached".to_string())
        }
    );
}

#[test]
fn mismatched_finish_does_not_clear_running_span() {
    let mut app = app();
    app.begin_working_span();
    let turn = app.prediction_state.turn();

    app.apply_event(TurnEvent::ThinkingStarted {
        agent: "Build".to_string(),
        turn_id: Some("live".to_string()),
    });
    app.apply_event(TurnEvent::AgentIdle {
        turn_id: Some("stale".to_string()),
        reason: IdleReason::Completed,
    });

    assert!(app.busy);
    assert!(app.span_started_at.is_some());
    assert_eq!(
        app.working_span_state,
        WorkingSpanState::Running {
            turn_id: Some("live".to_string())
        }
    );
    assert_eq!(app.prediction_state.turn(), turn);
}

#[test]
fn idle_reason_status_copy_matches_reason_severity() {
    let mut app = app();

    app.apply_event(TurnEvent::AgentIdle {
        turn_id: None,
        reason: IdleReason::Completed,
    });
    assert_eq!(app.idle_reason_status_text(), None);

    app.apply_event(TurnEvent::AgentIdle {
        turn_id: None,
        reason: IdleReason::NeedsIntervention {
            code: "agent_failed_to_progress".to_string(),
        },
    });
    let stalled = app.idle_reason_status_text().unwrap();
    assert!(stalled.contains("run `/goal resume`"));
    assert!(stalled.contains("send guidance"));

    app.apply_event(TurnEvent::AgentIdle {
        turn_id: None,
        reason: IdleReason::BudgetLimited,
    });
    assert!(
        app.idle_reason_status_text()
            .is_some_and(|text| text.contains("token budget reached"))
    );

    app.apply_event(TurnEvent::AgentIdle {
        turn_id: None,
        reason: IdleReason::GoalComplete,
    });
    let complete = app.idle_reason_status_text().unwrap();
    assert!(complete.contains("goal session completed"));
    assert!(!complete.contains("workspace"));
    assert!(!complete.contains("queue"));
}

#[test]
fn retracted_message_clears_span_without_finish() {
    let mut app = app();
    app.begin_working_span();
    let turn = app.prediction_state.turn();

    app.apply_event(TurnEvent::UserMessageRetracted);

    assert!(!app.busy);
    assert!(app.span_started_at.is_none());
    assert_eq!(app.working_span_state, WorkingSpanState::Idle);
    assert_eq!(app.prediction_state.turn(), turn);
}
