//! State machine of the one-time consented sandbox fallback dialog
//! ([`super::sandbox_fallback`]).

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use super::sandbox_fallback::{
    SANDBOX_FALLBACK_KEEP_REFUSING_ID, SANDBOX_FALLBACK_RUN_UNSANDBOXED_ID, SandboxFallbackPrompt,
    sandbox_fallback_prompt_text,
};
use super::{App, LocalChoice, LocalChoiceSelection};
use crate::tui::agent_runner::{AgentRunner, ControlRequest, TestRunnerOverrides};
use cockpit_client::presentation::TurnEvent;
use cockpit_config::extended::ApprovalMode;
use cockpit_core::tools::shell_sandbox::{
    APPARMOR_USERNS_FIX_COMMAND, APPARMOR_USERNS_PERSIST_COMMAND, UsernsRestriction,
};
use cockpit_proto::{Request, SandboxMode};

struct Fixture {
    app: App,
    control_rx: mpsc::Receiver<ControlRequest>,
    _tmp: tempfile::TempDir,
}

/// An interactive TUI attached to a (fixture) daemon session whose host
/// sandbox intent is fail-closed `Refuse`.
fn attached_refusing_app(approval_mode: ApprovalMode) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (record_tx, _record_rx) = mpsc::channel(8);
    let (control_tx, control_rx) = mpsc::channel(8);
    app.agent_runner = Some(Ok(AgentRunner::test_fixture(TestRunnerOverrides {
        record_tx: Some(record_tx),
        control_tx: Some(control_tx),
        events: Some(Arc::new(Mutex::new(Vec::new()))),
        ..Default::default()
    })));
    app.approval_mode = approval_mode;
    app.sandbox_intent = SandboxMode::Sandbox;
    app.sandbox_mode = SandboxMode::Refuse;
    Fixture {
        app,
        control_rx,
        _tmp: tmp,
    }
}

fn userns_refusal() -> TurnEvent {
    TurnEvent::SandboxUnavailable {
        remedy: UsernsRestriction::AppArmor.reason(),
        fix_command: Some(APPARMOR_USERNS_FIX_COMMAND.to_string()),
        persist_command: Some(APPARMOR_USERNS_PERSIST_COMMAND.to_string()),
    }
}

fn fallback_dialog_open(app: &App) -> bool {
    app.question_dialog.is_some()
        && matches!(
            app.pending_local_choice,
            Some(LocalChoice::SandboxFallback(_))
        )
}

/// What the input router does when the question dialog closes.
fn answer(app: &mut App, selected: Option<&str>) {
    app.question_dialog = None;
    app.resolve_local_choice(LocalChoiceSelection::Single(selected.map(str::to_string)));
}

fn set_sandbox_requests(rx: &mut mpsc::Receiver<ControlRequest>) -> Vec<Request> {
    let mut out = Vec::new();
    while let Ok(control) = rx.try_recv() {
        if matches!(control.request, Request::SetSandbox { .. }) {
            out.push(control.request);
        }
    }
    out
}

#[tokio::test]
async fn first_userns_refusal_opens_the_dialog_once() {
    let mut fixture = attached_refusing_app(ApprovalMode::Manual);
    let app = &mut fixture.app;

    app.apply_event(userns_refusal());
    assert!(fallback_dialog_open(app), "first refusal must ask");
    assert_eq!(app.sandbox_fallback_prompt, SandboxFallbackPrompt::Shown);
    // Opening the dialog changed nothing: still fail-closed, no request.
    assert_eq!(app.sandbox_mode, SandboxMode::Refuse);
    assert!(set_sandbox_requests(&mut fixture.control_rx).is_empty());
}

#[tokio::test]
async fn run_unsandboxed_sends_the_explicit_sandbox_off_request() {
    let mut fixture = attached_refusing_app(ApprovalMode::Manual);
    fixture.app.apply_event(userns_refusal());
    assert!(fallback_dialog_open(&fixture.app));

    answer(&mut fixture.app, Some(SANDBOX_FALLBACK_RUN_UNSANDBOXED_ID));

    let requests = set_sandbox_requests(&mut fixture.control_rx);
    assert!(
        matches!(
            requests.as_slice(),
            [Request::SetSandbox {
                mode: Some(SandboxMode::Off),
                container_network_enabled: None,
            }]
        ),
        "Run unsandboxed must take the persisted `/sandbox off` path: {requests:?}"
    );
    assert!(fixture.app.question_dialog.is_none());
}

#[tokio::test]
async fn keep_refusing_dismisses_and_is_not_reshown_this_session() {
    let mut fixture = attached_refusing_app(ApprovalMode::Manual);
    fixture.app.apply_event(userns_refusal());
    answer(&mut fixture.app, Some(SANDBOX_FALLBACK_KEEP_REFUSING_ID));

    assert!(fixture.app.question_dialog.is_none());
    assert!(fixture.app.pending_local_choice.is_none());
    assert!(set_sandbox_requests(&mut fixture.control_rx).is_empty());
    assert_eq!(fixture.app.sandbox_mode, SandboxMode::Refuse);

    // A later refusal (reattach replay, another bash call) does not ask again.
    fixture.app.apply_event(userns_refusal());
    assert!(!fallback_dialog_open(&fixture.app));
}

#[tokio::test]
async fn escape_is_keep_refusing() {
    let mut fixture = attached_refusing_app(ApprovalMode::Manual);
    fixture.app.apply_event(userns_refusal());
    answer(&mut fixture.app, None);

    assert!(set_sandbox_requests(&mut fixture.control_rx).is_empty());
    fixture.app.apply_event(userns_refusal());
    assert!(!fallback_dialog_open(&fixture.app));
}

#[tokio::test]
async fn yolo_never_shows_the_dialog() {
    let mut fixture = attached_refusing_app(ApprovalMode::Yolo);
    fixture.app.apply_event(userns_refusal());

    assert!(!fallback_dialog_open(&fixture.app));
    assert!(
        fixture.app.sandbox_down_notice.is_some(),
        "still fail-closed"
    );
    assert!(set_sandbox_requests(&mut fixture.control_rx).is_empty());
}

#[test]
fn detached_tui_never_shows_the_dialog() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.sandbox_intent = SandboxMode::Sandbox;
    app.sandbox_mode = SandboxMode::Refuse;
    app.apply_event(userns_refusal());
    assert!(!fallback_dialog_open(&app));
}

#[tokio::test]
async fn undiagnosed_refusal_does_not_offer_the_fallback() {
    let mut fixture = attached_refusing_app(ApprovalMode::Manual);
    fixture.app.apply_event(TurnEvent::SandboxUnavailable {
        remedy: "bwrap: execvp true: No such file or directory".to_string(),
        fix_command: None,
        persist_command: None,
    });
    assert!(!fallback_dialog_open(&fixture.app));
    assert_eq!(
        fixture.app.sandbox_fallback_prompt,
        SandboxFallbackPrompt::NotShown
    );
}

#[tokio::test]
async fn busy_screen_defers_the_dialog_until_the_other_dialog_closes() {
    let mut fixture = attached_refusing_app(ApprovalMode::Manual);
    let blocking = uuid::Uuid::new_v4();
    fixture.app.pending_local_choice = Some(LocalChoice::ExitGuard(blocking));

    fixture.app.apply_event(userns_refusal());
    assert!(!fallback_dialog_open(&fixture.app));
    assert_eq!(
        fixture.app.sandbox_fallback_prompt,
        SandboxFallbackPrompt::Deferred
    );

    fixture.app.pending_local_choice = None;
    fixture.app.retry_deferred_sandbox_fallback();
    assert!(fallback_dialog_open(&fixture.app));
    assert_eq!(
        fixture.app.sandbox_fallback_prompt,
        SandboxFallbackPrompt::Shown
    );
}

#[test]
fn prompt_names_reason_fix_persist_and_the_way_back() {
    let text = sandbox_fallback_prompt_text(
        &UsernsRestriction::AppArmor.reason(),
        Some(APPARMOR_USERNS_FIX_COMMAND),
        Some(APPARMOR_USERNS_PERSIST_COMMAND),
        Some("Narrower alternative: profile bwrap /usr/bin/bwrap flags=(unconfined) { userns, }"),
        None,
    );
    assert!(text.contains("restricted by AppArmor"), "{text}");
    assert!(text.contains(APPARMOR_USERNS_FIX_COMMAND));
    assert!(text.contains(APPARMOR_USERNS_PERSIST_COMMAND));
    assert!(text.contains("profile bwrap /usr/bin/bwrap"));
    assert!(text.contains("/sandbox on"));
    assert!(text.contains("nothing runs unconfined unless you choose it"));
}

#[test]
fn host_sandbox_recovery_suggests_sandbox_on_once() {
    use cockpit_proto::FeatureCapabilityState;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.sandbox_intent = SandboxMode::Off;
    app.sandbox_mode = SandboxMode::Off;
    let down = cockpit_core::daemon::session_worker::sandbox_capability_snapshot(
        FeatureCapabilityState::Missing,
        FeatureCapabilityState::Missing,
    );
    let up = cockpit_core::daemon::session_worker::sandbox_capability_snapshot(
        FeatureCapabilityState::Available,
        FeatureCapabilityState::Missing,
    );
    app.apply_host_capabilities(down.clone());
    assert!(app.toast.is_none());

    app.apply_host_capabilities(up.clone());
    let toast = app.toast.as_ref().expect("recovery hint");
    assert!(toast.text.contains("/sandbox on"), "{}", toast.text);
    // The hint never changes the mode.
    assert_eq!(app.sandbox_mode, SandboxMode::Off);

    app.toast = None;
    app.apply_host_capabilities(down);
    app.apply_host_capabilities(up);
    assert!(app.toast.is_none(), "one-time per session");
}

#[test]
fn always_available_host_does_not_nag_a_deliberate_off() {
    use cockpit_proto::FeatureCapabilityState;
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.sandbox_intent = SandboxMode::Off;
    app.sandbox_mode = SandboxMode::Off;
    let up = cockpit_core::daemon::session_worker::sandbox_capability_snapshot(
        FeatureCapabilityState::Available,
        FeatureCapabilityState::Missing,
    );
    app.apply_host_capabilities(up.clone());
    app.apply_host_capabilities(up);
    assert!(app.toast.is_none());
}
