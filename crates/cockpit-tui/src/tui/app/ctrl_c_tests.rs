use super::{CTRL_C_EXIT_WINDOW, CtrlCAction, decide_ctrl_c, input};
use crate::tui::agent_runner::{AgentRunner, TestRunnerOverrides};
use std::time::{Duration, Instant};

fn install_ephemeral_runner(
    app: &mut super::App,
) -> tokio::sync::mpsc::Receiver<crate::tui::agent_runner::ControlRequest> {
    let (control_tx, control_rx) = tokio::sync::mpsc::channel(1);
    let runner = AgentRunner::test_fixture(TestRunnerOverrides {
        control_tx: Some(control_tx),
        ..Default::default()
    });
    runner
        .ephemeral_owner
        .store(true, std::sync::atomic::Ordering::Release);
    app.agent_runner = Some(Ok(runner));
    control_rx
}

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

    use super::App;
    use crate::tui::history::{MarkdownOpts, render_entry};
    use crate::tui::theme::DISABLED;
    use cockpit_client::presentation::TurnEvent;
    use cockpit_config::extended::{DiffStyle, ThinkingDisplay};

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
    assert_eq!(rendered.lines[0].spans[0].style.fg, Some(DISABLED));
    assert!(
        rendered.lines[0]
            .spans
            .iter()
            .filter(|span| !span.content.is_empty())
            .all(|span| span.style.fg == Some(DISABLED)),
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
        false,
        &HashSet::new(),
        0,
        None,
    );
    assert_eq!(
        rendered.lines[0].spans[0].style.fg,
        Some(DISABLED),
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
    let _control_rx = install_ephemeral_runner(&mut app);

    app.busy = true;
    app.queue.push(input::optimistic_queue_item(
        "queued while busy".to_string(),
    ));

    let exit = app.handle_key(ctrl('d'));

    assert!(!exit, "first busy ctrl+d should guard instead of exiting");
    assert!(app.ctrl_c_armed_at.is_none(), "ctrl+d must not arm ctrl+c");
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("exit check is pending");
    app.apply_control_request_outcome(
        request_id,
        cockpit_client::presentation::ControlRequestOutcome::ExitGuardStatus {
            ephemeral_owner: true,
            has_live_work: true,
        },
    );
    assert!(
        app.question_dialog.is_some(),
        "daemon-confirmed busy ephemeral ctrl+d must offer the exit choice"
    );
    assert_eq!(
        app.queue.len(),
        1,
        "opening the exit choice must not cancel or discard queued work"
    );
}

#[test]
fn scheduled_work_ctrl_d_uses_guarded_quit_path() {
    use super::{ActiveSchedule, App};
    use std::time::Instant;
    use uuid::Uuid;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let _control_rx = install_ephemeral_runner(&mut app);
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
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("exit check is pending");
    app.apply_control_request_outcome(
        request_id,
        cockpit_client::presentation::ControlRequestOutcome::ExitGuardStatus {
            ephemeral_owner: true,
            has_live_work: true,
        },
    );
    assert!(app.question_dialog.is_some());
    assert!(app.ctrl_c_armed_at.is_none());
}

#[test]
fn exit_guard_stop_all_cancels_only_the_attached_session() {
    use super::App;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
    let runner = AgentRunner::test_fixture(TestRunnerOverrides {
        control_tx: Some(control_tx),
        ..Default::default()
    });
    runner
        .ephemeral_owner
        .store(true, std::sync::atomic::Ordering::Release);
    app.agent_runner = Some(Ok(runner));

    app.resolve_exit_guard_choice(Some("stop_all"));

    let control = control_rx.try_recv().expect("stop-all control request");
    assert!(matches!(
        control.request,
        cockpit_proto::Request::CancelAllSessionWork
    ));
}

#[test]
fn modal_state_ctrl_d_uses_guarded_quit_path() {
    use super::App;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.pending_prune_confirm = true;

    let exit = app.handle_key(ctrl('d'));

    assert!(!exit, "ctrl+d should guard while confirm state is pending");
    assert!(app.ctrl_c_armed_at.is_none());
    assert!(
        app.pending_prune_confirm,
        "guarded ctrl+d must not answer or clear the pending modal"
    );
}

#[test]
fn durable_control_receipt_fences_every_guarded_exit() {
    use super::{App, ControlApplied, PendingControlRequest};

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let request_id = cockpit_client::presentation::ControlRequestId(41);
    app.pending_control_requests.insert(
        request_id,
        PendingControlRequest::new("durable mutation", ControlApplied::None),
    );

    assert!(app.has_unsettled_local_authority());
    assert!(!app.request_guarded_exit(), "/exit must remain fenced");
    assert!(!app.handle_key(ctrl('d')), "Ctrl+D must remain fenced");
    app.ctrl_c_armed_at = Some(Instant::now());
    assert!(!app.handle_ctrl_c(), "double Ctrl+C must remain fenced");
    assert!(
        app.toast
            .as_ref()
            .is_some_and(|toast| toast.text.contains("verified terminal state")),
        "all exit paths use the same authority-settlement status"
    );

    app.pending_control_requests.remove(&request_id);
    assert!(!app.has_unsettled_local_authority());
    assert!(app.request_guarded_exit());
}

#[test]
fn exit_routes_share_the_app_wide_authority_gate() {
    let terminal_controls = include_str!("terminal_controls.rs");
    let input = include_str!("input.rs");
    let slash = include_str!("slash.rs");

    assert!(
        terminal_controls.contains("CtrlCAction::Exit => self.request_guarded_exit()")
            || terminal_controls
                .contains("CtrlCAction::Exit => {\n                self.request_guarded_exit()")
    );
    assert!(input.contains("return self.request_guarded_exit();"));
    assert!(
        slash.contains(
            "fn run_exit(app: &mut App, _: &str) -> bool {\n    app.request_guarded_exit()"
        )
    );
}

#[test]
fn async_authority_inventory_is_central_and_programmatic_exit_is_fenced() {
    let terminal_controls = include_str!("terminal_controls.rs");
    let app = include_str!("mod.rs");
    let async_action = include_str!("../async_action.rs");

    assert!(terminal_controls.contains("self.async_actions.has_unsettled_local_authority()"));
    assert!(
        !terminal_controls.contains("AsyncActionKind::"),
        "App exit code must not maintain a second action-label inventory"
    );
    assert!(async_action.contains("pub fn authority(&self)"));
    assert!(async_action.contains("_ => Unclassified"));
    assert!(async_action.contains("!matches!(self, Self::ReadOnly)"));
    assert!(app.contains("if self.exit_requested && !self.has_unsettled_local_authority()"));
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

/// Issue #546: quitting never depends on daemon authority. When the daemon
/// refuses the exit check with a typed authorization error (this connection
/// lost owner authority), the user is told how to leave and the next exit
/// request quits without asking the daemon again.
#[test]
fn unauthorized_exit_check_lets_the_next_exit_quit_without_the_daemon() {
    use super::App;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let mut control_rx = install_ephemeral_runner(&mut app);

    assert!(!app.request_guarded_exit(), "first exit asks the daemon");
    let sent = control_rx.try_recv().expect("exit check is sent");
    assert!(matches!(
        sent.request,
        cockpit_proto::Request::ExitGuardStatus
    ));
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("exit check is pending");
    app.apply_control_request_outcome(
        request_id,
        cockpit_client::presentation::ControlRequestOutcome::Unauthorized(
            "daemon request: daemon error: authorization: request requires the local owner"
                .to_string(),
        ),
    );
    assert!(
        !app.exit_requested,
        "a refused check does not exit by itself"
    );
    assert!(
        app.toast
            .as_ref()
            .is_some_and(|toast| toast.text.contains("quit without the daemon check")),
        "the refusal tells the user how to quit"
    );

    assert!(
        app.request_guarded_exit(),
        "the next exit request quits without daemon authority"
    );
    assert!(
        control_rx.try_recv().is_err(),
        "no second exit check is sent"
    );
}

/// Run one exit attempt that the daemon answers with `outcome`.
fn exit_check_answered(
    app: &mut super::App,
    control_rx: &mut tokio::sync::mpsc::Receiver<crate::tui::agent_runner::ControlRequest>,
    outcome: cockpit_client::presentation::ControlRequestOutcome,
) {
    assert!(!app.request_guarded_exit(), "exit asks the daemon");
    let _sent = control_rx.try_recv().expect("exit check is sent");
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("exit check is pending");
    app.apply_control_request_outcome(request_id, outcome);
}

/// C4 (issue #546 r2): a delivered non-authorization refusal (for example a
/// concurrent detach decision) never disables the daemon's exit check.
#[test]
fn unrelated_exit_check_refusal_keeps_the_guard() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let mut control_rx = install_ephemeral_runner(&mut app);
    exit_check_answered(
        &mut app,
        &mut control_rx,
        cockpit_client::presentation::ControlRequestOutcome::Rejected(
            "daemon request: daemon error: internal: another client is deciding how to detach live ephemeral work"
                .to_string(),
        ),
    );
    assert!(app.exit_check_escape.is_none());
    assert!(
        !app.request_guarded_exit(),
        "the next exit still asks the daemon"
    );
    assert!(control_rx.try_recv().is_ok(), "a fresh exit check is sent");
}

/// C4: a fenced (stale) receipt never arms the escape.
#[test]
fn fenced_exit_check_refusal_does_not_arm_the_escape() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let mut control_rx = install_ephemeral_runner(&mut app);
    assert!(!app.request_guarded_exit());
    let _request = control_rx.try_recv().unwrap();
    let id = *app.pending_control_requests.keys().next().unwrap();
    app.fence_pending_control_request(id);
    app.apply_control_request_outcome(
        id,
        cockpit_client::presentation::ControlRequestOutcome::Unauthorized(
            "authorization: request requires the local owner".into(),
        ),
    );
    assert!(app.exit_check_escape.is_none());
}

/// C4: the escape is one-shot and bound to its attachment: a session reset
/// voids it, and a successful exit check clears it.
#[test]
fn exit_check_escape_is_one_shot_and_bound_to_its_attachment() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let mut control_rx = install_ephemeral_runner(&mut app);
    let unauthorized = || {
        cockpit_client::presentation::ControlRequestOutcome::Unauthorized(
            "authorization: request requires the local owner".into(),
        )
    };
    exit_check_answered(&mut app, &mut control_rx, unauthorized());
    assert!(app.exit_check_escape.is_some());
    app.reset_session_live_state();
    assert!(
        app.exit_check_escape.is_none(),
        "exit recovery from an old session must not bypass a new session's work check"
    );

    // The reset session's successor attaches a new runner.
    control_rx = install_ephemeral_runner(&mut app);
    exit_check_answered(&mut app, &mut control_rx, unauthorized());
    assert!(app.exit_check_escape.is_some());
    // The very next exit attempt uses it ...
    assert!(
        app.request_guarded_exit(),
        "the armed attempt quits locally"
    );
    assert!(control_rx.try_recv().is_err(), "without asking the daemon");
    // ... and only that one: it is not sticky.
    app.exit_requested = false;
    assert!(app.exit_check_escape.is_none());
    assert!(
        !app.request_guarded_exit(),
        "a later exit asks the daemon again"
    );
    assert!(control_rx.try_recv().is_ok());
    // A successful daemon answer to that check voids an escape armed
    // meanwhile (for example by a parallel undelivered check).
    let id = *app.pending_control_requests.keys().next().unwrap();
    app.exit_check_escape = app.current_exit_check_binding();
    assert!(app.exit_check_escape.is_some());
    app.apply_control_request_outcome(
        id,
        cockpit_client::presentation::ControlRequestOutcome::ExitGuardStatus {
            ephemeral_owner: true,
            has_live_work: true,
        },
    );
    assert!(app.exit_check_escape.is_none());

    // An escape armed for another attachment is consumed without effect.
    app.exit_check_escape = Some(super::ExitCheckBinding {
        session_id: uuid::Uuid::new_v4(),
        attachment_epoch: 99,
    });
    app.question_dialog = None;
    app.pending_local_choice = None;
    assert!(
        !app.request_guarded_exit(),
        "a foreign binding never skips the check"
    );
    assert!(
        app.exit_check_escape.is_none(),
        "the escape is consumed by one attempt"
    );
}

/// C2 (issue #546 r2): an exit check that cannot even be queued (the
/// runner's control receiver is gone) never strands quit: the next exit
/// leaves without the daemon.
#[test]
fn immediately_undelivered_exit_check_can_quit_on_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let control_rx = install_ephemeral_runner(&mut app);
    drop(control_rx);
    assert!(!app.request_guarded_exit());
    assert!(app.pending_control_requests.is_empty());
    assert!(
        app.request_guarded_exit(),
        "an immediately undelivered check must allow the local exit on retry"
    );
}

/// C2: the same when the control channel is full.
#[test]
fn exit_check_rejected_by_a_full_control_channel_can_quit_on_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let _control_rx = install_ephemeral_runner(&mut app);
    let control_tx = app
        .agent_runner
        .as_ref()
        .and_then(|runner| runner.as_ref().ok())
        .map(|runner| runner.control_tx.clone())
        .expect("runner");
    // Fill the one-slot channel with an unrelated request.
    let (response_tx, _response_rx) = tokio::sync::oneshot::channel();
    control_tx
        .try_send(crate::tui::agent_runner::ControlRequest {
            request: cockpit_proto::Request::Prune,
            intended_session_id: uuid::Uuid::new_v4(),
            intended_attachment_epoch: 0,
            response_tx,
        })
        .expect("fill the control channel");
    assert!(!app.request_guarded_exit());
    assert!(app.pending_control_requests.is_empty());
    assert!(
        app.request_guarded_exit(),
        "a full control channel never strands quit"
    );
}

/// Reviewer C2 sibling: transport failure after the runner accepts a control
/// is not a delivered policy refusal. It must permit the bound local retry.
#[test]
fn transport_failed_exit_check_can_quit_on_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let mut control_rx = install_ephemeral_runner(&mut app);
    let outcome = crate::tui::agent_runner::control_response_outcome(Err(
        "daemon request: daemon client task has stopped"
            .to_string()
            .into(),
    ));
    exit_check_answered(&mut app, &mut control_rx, outcome);
    assert!(app.pending_control_requests.is_empty());
    assert!(
        app.request_guarded_exit(),
        "a transport-failed exit check must permit a local retry, like a closed control channel"
    );
}

async fn drain_exit_control_receipt(app: &mut super::App) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !app.pending_control_requests.is_empty() {
            app.drain_agent_events();
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the accepted control settles through the runner event queue");
}

/// Exercise real DaemonClient failures through the accepted response channel,
/// production conversion, runner event queue, App settlement and local retry.
#[tokio::test]
async fn transport_failed_exit_guard_settles_closed_task_dropped_reply_and_timeout() {
    for failure in ["closed task", "dropped reply", "timeout"] {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = super::App::new(Some(tmp.path()), false);
        app.dialog = crate::tui::settings::Dialog::None;
        let mut control_rx = install_ephemeral_runner(&mut app);
        let (requests, mut request_rx) =
            tokio::sync::mpsc::channel::<cockpit_client::InProcessRequest>(1);
        let (_events, event_rx) = tokio::sync::mpsc::channel(1);
        let client =
            cockpit_client::DaemonClient::from_in_process(cockpit_client::InProcessConnection {
                requests,
                events: event_rx,
            });
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let daemon = if failure == "closed task" {
            drop(request_rx);
            None
        } else {
            Some(tokio::spawn(async move {
                let request = request_rx
                    .recv()
                    .await
                    .expect("control reaches the daemon client");
                assert!(matches!(
                    request.request,
                    cockpit_proto::Request::ExitGuardStatus
                ));
                if failure == "timeout" {
                    release_rx.await.unwrap();
                }
                drop(request.reply);
            }))
        };
        assert!(!app.request_guarded_exit());
        let control = control_rx.try_recv().expect("control accepted by runner");
        let result = client
            .request_with_timeout(control.request, Duration::from_millis(25))
            .await;
        let error = result
            .as_ref()
            .expect_err("transport must fail")
            .to_string();
        match failure {
            "closed task" => assert!(error.contains("task has stopped")),
            "dropped reply" => assert!(error.contains("dropped reply channel")),
            "timeout" => assert!(error.contains("request timed out")),
            _ => unreachable!(),
        }
        control
            .response_tx
            .send(crate::tui::agent_runner::control_request_result(result))
            .unwrap();
        drain_exit_control_receipt(&mut app).await;
        assert!(!app.exit_requested, "failure alone never exits");
        assert!(
            app.request_guarded_exit(),
            "{failure} permits the bound local retry"
        );
        assert!(
            control_rx.try_recv().is_err(),
            "retry requires no daemon response"
        );
        if failure == "timeout" {
            release_tx.send(()).unwrap();
        }
        if let Some(daemon) = daemon {
            daemon.await.unwrap();
        }
    }
}

/// A mutation already accepted by the transport can still complete after
/// timeout. Its receipt must retain uncertainty through the real conversion.
#[tokio::test]
async fn timed_out_mutation_stays_transport_unknown_after_delivery() {
    let (requests, mut request_rx) = tokio::sync::mpsc::channel(1);
    let (_events, events) = tokio::sync::mpsc::channel(1);
    let client =
        cockpit_client::DaemonClient::from_in_process(cockpit_client::InProcessConnection {
            requests,
            events,
        });
    let mutation = tokio::spawn(async move {
        client
            .request_with_timeout(cockpit_proto::Request::Prune, Duration::from_millis(25))
            .await
    });
    let delivered = request_rx.recv().await.unwrap();
    assert!(matches!(delivered.request, cockpit_proto::Request::Prune));
    let result = mutation.await.unwrap();
    assert!(
        result.is_err(),
        "timeout cannot manufacture a daemon refusal"
    );
    let outcome = crate::tui::agent_runner::control_response_outcome(
        crate::tui::agent_runner::control_request_result(result),
    );
    assert!(
        matches!(
            outcome,
            cockpit_client::presentation::ControlRequestOutcome::TransportFailed(_)
        ),
        "an admitted mutation stays delivery/effect-unknown, never NotDelivered"
    );
    assert!(
        delivered
            .reply
            .send(Ok(cockpit_proto::Response::Ack))
            .is_err(),
        "late mutation completion has no expired reply receiver"
    );
}

/// Inverse: actual delivered Internal/policy refusals do not masquerade as
/// transport loss. Typed Authorization still permits local recovery.
#[tokio::test]
async fn control_request_delivered_refusal_preserves_the_exit_guard_contract() {
    for code in [
        cockpit_proto::ErrorCode::Internal,
        cockpit_proto::ErrorCode::Conflict,
        cockpit_proto::ErrorCode::Authorization,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = super::App::new(Some(tmp.path()), false);
        app.dialog = crate::tui::settings::Dialog::None;
        let mut control_rx = install_ephemeral_runner(&mut app);
        let (requests, mut request_rx) =
            tokio::sync::mpsc::channel::<cockpit_client::InProcessRequest>(1);
        let (_events, events) = tokio::sync::mpsc::channel(1);
        let client =
            cockpit_client::DaemonClient::from_in_process(cockpit_client::InProcessConnection {
                requests,
                events,
            });
        let authorization = code == cockpit_proto::ErrorCode::Authorization;
        let daemon = tokio::spawn(async move {
            let request = request_rx.recv().await.unwrap();
            request
                .reply
                .send(Err(cockpit_proto::ErrorPayload {
                    code,
                    message: "another client is deciding how to detach live work".into(),
                }))
                .unwrap();
        });
        assert!(!app.request_guarded_exit());
        let control = control_rx.try_recv().unwrap();
        let result = client.request(control.request).await;
        assert!(result.as_ref().expect("response delivered").is_err());
        control
            .response_tx
            .send(crate::tui::agent_runner::control_request_result(result))
            .unwrap();
        drain_exit_control_receipt(&mut app).await;
        assert_eq!(app.exit_check_escape.is_some(), authorization);
        assert_eq!(
            app.request_guarded_exit(),
            authorization,
            "only delivered Authorization permits the local retry"
        );
        if authorization {
            assert!(control_rx.try_recv().is_err());
        } else {
            assert!(matches!(
                control_rx.try_recv().unwrap().request,
                cockpit_proto::Request::ExitGuardStatus
            ));
        }
        daemon.await.unwrap();
    }
}

#[tokio::test]
async fn runner_teardown_after_accepting_exit_guard_allows_the_local_retry() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let mut control_rx = install_ephemeral_runner(&mut app);
    assert!(!app.request_guarded_exit());
    drop(
        control_rx
            .try_recv()
            .expect("runner accepted the exit check"),
    );
    drain_exit_control_receipt(&mut app).await;
    assert!(app.request_guarded_exit());
    assert!(control_rx.try_recv().is_err());
}

#[test]
fn fenced_transport_failed_exit_check_does_not_arm_the_escape() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = super::App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let mut control_rx = install_ephemeral_runner(&mut app);
    assert!(!app.request_guarded_exit());
    let _control = control_rx.try_recv().unwrap();
    let id = *app.pending_control_requests.keys().next().unwrap();
    app.fence_pending_control_request(id);
    app.apply_control_request_outcome(
        id,
        crate::tui::agent_runner::control_response_outcome(
            crate::tui::agent_runner::control_request_result(Err(anyhow::anyhow!(
                "request timed out"
            ))),
        ),
    );
    assert!(app.pending_control_requests.is_empty());
    assert!(app.exit_check_escape.is_none());
    assert!(
        !app.request_guarded_exit(),
        "a fenced transport failure preserves the guard"
    );
    assert!(control_rx.try_recv().is_ok());
}
