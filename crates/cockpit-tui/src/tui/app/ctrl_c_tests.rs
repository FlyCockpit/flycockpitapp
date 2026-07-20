use super::{CTRL_C_EXIT_WINDOW, CtrlCAction, decide_ctrl_c, input};
use std::time::{Duration, Instant};

/// Idle + single (first) press: arm the window + show hint only,
/// nothing to interrupt. The window is armed at `now`.
#[test]
fn idle_first_press_arms_only() {
    let now = Instant::now();
    let (action, armed) = decide_ctrl_c(now, None, CTRL_C_EXIT_WINDOW, false);
    assert_eq!(action, CtrlCAction::ArmOnly);
    assert_eq!(armed, Some(now));
}

/// Busy + single (first) press: arm the window AND interrupt the agent.
#[test]
fn busy_first_press_arms_and_interrupts() {
    let now = Instant::now();
    let (action, armed) = decide_ctrl_c(now, None, CTRL_C_EXIT_WINDOW, true);
    assert_eq!(action, CtrlCAction::ArmAndInterrupt);
    assert_eq!(armed, Some(now));
}

/// Second press inside the window exits — regardless of agent state.
/// During a run, the first press already interrupted; this second one
/// is the "interrupt AND exit" case.
#[test]
fn second_press_within_window_exits_when_busy() {
    let first = Instant::now();
    let second = first + Duration::from_millis(200); // < 500ms
    let (action, armed) = decide_ctrl_c(second, Some(first), CTRL_C_EXIT_WINDOW, true);
    assert_eq!(action, CtrlCAction::Exit);
    assert_eq!(armed, None);
}

/// Second press inside the window exits even when idle (idle + two fast
/// presses = exit).
#[test]
fn second_press_within_window_exits_when_idle() {
    let first = Instant::now();
    let second = first + Duration::from_millis(499);
    let (action, _armed) = decide_ctrl_c(second, Some(first), CTRL_C_EXIT_WINDOW, false);
    assert_eq!(action, CtrlCAction::Exit);
}

/// Exactly at the window boundary still counts as a second press
/// (`<=` window).
#[test]
fn second_press_at_window_boundary_exits() {
    let first = Instant::now();
    let second = first + CTRL_C_EXIT_WINDOW;
    let (action, _armed) = decide_ctrl_c(second, Some(first), CTRL_C_EXIT_WINDOW, false);
    assert_eq!(action, CtrlCAction::Exit);
}

/// Two presses spaced further apart than the window NEVER exit: the
/// second is treated as a fresh first press (re-armed at `now`).
#[test]
fn presses_outside_window_never_exit() {
    let first = Instant::now();
    let second = first + Duration::from_millis(501); // > 500ms
    let (action, armed) = decide_ctrl_c(second, Some(first), CTRL_C_EXIT_WINDOW, false);
    assert_eq!(action, CtrlCAction::ArmOnly);
    assert_eq!(
        armed,
        Some(second),
        "a lapsed window re-arms at the new press"
    );

    // A steady stream of slow presses interrupts repeatedly, never
    // exits: each press is > window after the previous.
    let third = second + Duration::from_millis(600);
    let (action, armed) = decide_ctrl_c(third, Some(second), CTRL_C_EXIT_WINDOW, true);
    assert_eq!(action, CtrlCAction::ArmAndInterrupt);
    assert_eq!(armed, Some(third));
}

/// The window slides from the *last* press: a press just inside the
/// window of the immediately-previous press exits, even if the very
/// first press was long ago.
#[test]
fn window_slides_from_last_press() {
    let t0 = Instant::now();
    // First press, armed at t0.
    let (_a, armed) = decide_ctrl_c(t0, None, CTRL_C_EXIT_WINDOW, false);
    // A press > window later: fresh first press, re-arm.
    let t1 = t0 + Duration::from_millis(800);
    let (a, armed) = decide_ctrl_c(t1, armed, CTRL_C_EXIT_WINDOW, false);
    assert_eq!(a, CtrlCAction::ArmOnly);
    // A press < window after t1: exits (slides from t1, not t0).
    let t2 = t1 + Duration::from_millis(100);
    let (a, _armed) = decide_ctrl_c(t2, armed, CTRL_C_EXIT_WINDOW, false);
    assert_eq!(a, CtrlCAction::Exit);
}

#[test]
fn auto_prune_notice_renders_muted() {
    use std::collections::HashSet;

    use ratatui::style::Color;

    use super::App;
    use crate::config::extended::{DiffStyle, ThinkingDisplay};
    use crate::engine::agent::TurnEvent;
    use crate::tui::history::{MarkdownOpts, render_entry};
    use crate::tui::theme::MUTED_COLOR_INDEX;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.apply_event(TurnEvent::Pruned {
        auto: true,
        bodies: 1,
        tokens_saved: 42,
        elided: Vec::new(),
        trigger_reason: Some("cache_already_cold".to_string()),
        cache_break: false,
    });

    let rendered = render_entry(
        app.history.last().expect("auto-prune notice is pushed"),
        100,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        DiffStyle::SideBySide,
        false,
        &HashSet::new(),
        0,
        None,
    );

    assert_eq!(rendered.lines.len(), 1);
    let rendered_line = rendered.lines[0]
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    assert!(rendered_line.contains("cache already cold"));
    assert_eq!(
        rendered.lines[0].spans[0].style.fg,
        Some(Color::Indexed(MUTED_COLOR_INDEX))
    );
    assert!(
        rendered.lines[0]
            .spans
            .iter()
            .filter(|span| !span.content.is_empty())
            .all(|span| span.style.fg == Some(Color::Indexed(MUTED_COLOR_INDEX))),
        "every visible span in the auto-prune notice should be muted"
    );

    app.apply_event(TurnEvent::Pruned {
        auto: false,
        bodies: 1,
        tokens_saved: 42,
        elided: Vec::new(),
        trigger_reason: None,
        cache_break: false,
    });
    let rendered = render_entry(
        app.history.last().expect("manual prune notice is pushed"),
        100,
        ThinkingDisplay::Condensed,
        MarkdownOpts::default(),
        DiffStyle::SideBySide,
        false,
        &HashSet::new(),
        0,
        None,
    );
    assert_eq!(
        rendered.lines[0].spans[0].style.fg,
        Some(Color::Indexed(MUTED_COLOR_INDEX)),
        "manual /prune confirmation should use the shared plain-line muted styling"
    );
}

/// Regression (implementation note, candidate
/// "queued-message state"): a first ctrl+c while busy must interrupt
/// (not exit) AND clear the locally-mirrored queue of messages the user
/// submitted during the working span. The daemon discards those queued
/// messages on the matching `CancelTurn`, so leaving them rendered above
/// the composer would falsely imply they are still pending. Exercised on
/// the real `App` so the `handle_ctrl_c` action wiring (not just the pure
/// decision) is covered.
#[test]
fn busy_ctrl_c_interrupts_and_clears_the_queue() {
    use super::App;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    // Simulate an in-flight span with two messages queued during it.
    app.busy = true;
    app.queue
        .push(input::optimistic_queue_item("queued one".to_string()));
    app.queue
        .push(input::optimistic_queue_item("queued two".to_string()));

    // First ctrl+c while busy: interrupt (returns false = do not exit).
    let exit = app.handle_ctrl_c();
    assert!(!exit, "a first ctrl+c while busy interrupts, never exits");
    assert!(
        app.queue.is_empty(),
        "the queued messages are dropped so the cancel returns to idle"
    );
    // The exit window is armed (a second fast press would exit).
    assert!(app.ctrl_c_armed_at.is_some());
}

/// A ctrl+c while idle must not clear a draft queue spuriously: an idle
/// press only arms the exit hint (there is no working span to cancel), so
/// any locally-queued content is left intact.
#[test]
fn idle_ctrl_c_leaves_queue_intact() {
    use super::App;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.busy = false;
    app.queue
        .push(input::optimistic_queue_item("still pending".to_string()));

    let exit = app.handle_ctrl_c();
    assert!(!exit, "a first idle ctrl+c only arms the exit hint");
    assert_eq!(
        app.queue
            .iter()
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>(),
        vec!["still pending"],
        "an idle ctrl+c never drops queued content (nothing to cancel)"
    );
}

fn ctrl(ch: char) -> crossterm::event::KeyEvent {
    crossterm::event::KeyEvent {
        code: crossterm::event::KeyCode::Char(ch),
        modifiers: crossterm::event::KeyModifiers::CONTROL,
        kind: crossterm::event::KeyEventKind::Press,
        state: crossterm::event::KeyEventState::empty(),
    }
}

#[test]
fn idle_empty_ctrl_d_exits_immediately() {
    use super::App;
    use crate::tui::settings::Dialog;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = Dialog::None;

    let exit = app.handle_key(ctrl('d'));

    assert!(exit, "idle ctrl+d keeps the direct EOF-style exit");
    assert!(
        app.ctrl_c_armed_at.is_none(),
        "direct ctrl+d must not route through the guarded ctrl+c state"
    );
}

#[test]
fn busy_ctrl_d_uses_guarded_quit_path() {
    use super::App;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.busy = true;
    app.queue.push(input::optimistic_queue_item(
        "queued while busy".to_string(),
    ));

    let exit = app.handle_key(ctrl('d'));

    assert!(!exit, "first busy ctrl+d should guard instead of exiting");
    assert!(
        app.ctrl_c_armed_at.is_some(),
        "guarded ctrl+d should arm the same exit window as ctrl+c"
    );
    assert!(
        app.queue.is_empty(),
        "guarded busy ctrl+d should reuse ctrl+c interrupt cleanup"
    );
}

#[test]
fn scheduled_work_ctrl_d_uses_guarded_quit_path() {
    use super::{ActiveSchedule, App};
    use std::time::Instant;
    use uuid::Uuid;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.active_schedules.insert(
        "sched-1".to_string(),
        ActiveSchedule {
            session_id: Uuid::new_v4(),
            label: "background task".to_string(),
            kind: "background".to_string(),
            iteration: 0,
            last_activity: Instant::now(),
        },
    );

    let exit = app.handle_key(ctrl('d'));

    assert!(
        !exit,
        "ctrl+d should not directly exit while scheduled/background work exists"
    );
    assert!(app.ctrl_c_armed_at.is_some());
}

#[test]
fn modal_state_ctrl_d_uses_guarded_quit_path() {
    use super::App;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.pending_prune_confirm = true;

    let exit = app.handle_key(ctrl('d'));

    assert!(!exit, "ctrl+d should guard while confirm state is pending");
    assert!(app.ctrl_c_armed_at.is_some());
    assert!(
        app.pending_prune_confirm,
        "guarded ctrl+d must not answer or clear the pending modal"
    );
}

#[test]
fn bare_note_shows_usage_only() {
    use super::{App, HistoryEntry, Overlay};
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.handle_note_command("");
    app.handle_note_command("   ");

    assert!(
        !matches!(app.overlay, Overlay::Notes(_)),
        "bare /note never opens scratchpad"
    );
    let usage: Vec<&String> = app
        .history
        .iter()
        .filter_map(|e| match e {
            HistoryEntry::Plain { line } if line.contains("Usage: `/note") => Some(line),
            _ => None,
        })
        .collect();
    assert_eq!(usage.len(), 2, "each bare /note shows the usage row");
    assert!(
        !app.history
            .iter()
            .any(|e| matches!(e, HistoryEntry::UserNote { .. })),
        "no note event is recorded for bare /note"
    );
}

/// `/note <text>` before a session exists shows the same "send a message
/// first" error as `/rename`/`/export` and records no note (no phantom
/// session).
#[test]
fn note_without_session_shows_send_first_error() {
    use super::{App, HistoryEntry};
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    assert!(app.launch.session_id.is_none(), "no session at launch");

    app.handle_note_command("remember this");

    assert!(
        app.history.iter().any(|e| matches!(
            e,
            HistoryEntry::Plain { line } if line.contains("send a message first")
        )),
        "shows the shared no-session error"
    );
    assert!(
        !app.history
            .iter()
            .any(|e| matches!(e, HistoryEntry::UserNote { .. })),
        "no note row is added without a session"
    );
}
