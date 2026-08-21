use super::{App, Overlay};
use crate::tui::agent_runner::{AgentRunner, AttachedRequest, ClientTasks, UsageCounts};
use crate::tui::async_action::{AsyncActionKind, AsyncActionPayload, AsyncActionResult};
use crate::tui::skills_pane::{SkillsPaneFetchResult, SkillsPaneSource};
use cockpit_core::daemon::proto::{Request, Response, SkillSummary};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

fn app_for_skills(tmp: &tempfile::TempDir) -> App {
    let scan = tmp.path().join("skills");
    fs::create_dir_all(&scan).unwrap();
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    fs::write(
        cockpit.join("config.json"),
        serde_json::json!({
            "skills": {
                "scan_dirs": [scan.to_string_lossy()]
            }
        })
        .to_string(),
    )
    .unwrap();
    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(tmp.path()),
        || App::new(Some(tmp.path()), false),
    )
}

fn open_skills_pane_trusted(app: &mut App, tmp: &tempfile::TempDir) {
    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(tmp.path()),
        || app.open_skills_pane(),
    );
}

fn runner_with_attached_request_tx(
    attached_request_tx: mpsc::Sender<AttachedRequest>,
) -> AgentRunner {
    let (input_tx, _input_rx) = mpsc::channel::<crate::tui::agent_runner::RunnerInput>(1);
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, _control_rx) = mpsc::channel(1);
    AgentRunner {
        input_tx,
        record_tx,
        control_tx,
        attached_request_tx,
        events: Arc::new(Mutex::new(Vec::new())),
        event_notify: Arc::new(tokio::sync::Notify::new()),
        active_agent: Arc::new(Mutex::new("Build".to_string())),
        active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
        skill_inventory_names: Arc::new(Mutex::new(None)),
        foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
        active_model_state: None,
        session_id_state: Arc::new(Mutex::new(uuid::Uuid::new_v4())),
        attachment_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        submission_session_tx: tokio::sync::watch::channel(
            crate::tui::agent_runner::SubmissionSessionBinding::unbound(),
        )
        .0,
        awaiting_durable: Default::default(),
        short_id: "abc123".to_string(),
        project_id: "project".to_string(),
        usage: UsageCounts::default(),
        owns_daemon: false,
        socket: PathBuf::from("/tmp/cockpit-test.sock"),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        current_client: None,
        attach_context: None,
        last_applied_seq: None,
        client_tasks: ClientTasks::default(),
        #[cfg(test)]
        test_session_switch_rx: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        test_force_can_switch: false,
        test_advance_epoch_when_switch_task_created: false,
    }
}

fn summary(name: &str, description: &str, source: &str) -> SkillSummary {
    SkillSummary {
        name: name.to_string(),
        description: description.to_string(),
        source: source.to_string(),
        user_invocable: true,
    }
}

fn skills_text(app: &App) -> String {
    let Overlay::Skills(pane) = &app.overlay else {
        panic!("skills pane should be open");
    };
    pane.body_text_for_test()
}

fn skills_generation(app: &App) -> u64 {
    let Overlay::Skills(pane) = &app.overlay else {
        panic!("skills pane should be open");
    };
    pane.generation_for_test()
}

async fn drain_until_idle(app: &mut App) {
    for _ in 0..100 {
        tokio::task::yield_now().await;
        app.drain_async_actions();
        if app.async_actions.pending_count() == 0 {
            app.drain_async_actions();
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("async action did not complete");
}

#[tokio::test]
async fn skills_pane_uses_attached_client_when_runner_present() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_for_skills(&tmp);
    let (attached_request_tx, mut attached_request_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_attached_request_tx(attached_request_tx)));

    open_skills_pane_trusted(&mut app, &tmp);

    assert_eq!(
        app.async_actions.pending_kinds(),
        vec![AsyncActionKind::DaemonRpc("skills.list")]
    );
    let attached = attached_request_rx.recv().await.unwrap();
    match attached.request {
        Request::GetInventoryBundle {
            project_root,
            selected_agent,
            ..
        } => {
            assert_eq!(project_root, tmp.path().to_string_lossy().into_owned());
            assert_eq!(selected_agent, "Build");
        }
        other => panic!("unexpected request: {other:?}"),
    }
    attached
        .response_tx
        .send(Ok(Response::InventoryBundle {
            selected_agent: "Build".into(),
            agents: Vec::new(),
            models: Vec::new(),
            skills: vec![summary("session-only", "from attached session", "/session")],
            session_generation: 0,
            config_generation: 0,
            inventory_generation: 0,
        }))
        .unwrap();

    drain_until_idle(&mut app).await;

    let text = skills_text(&app);
    assert!(text.contains("session-only"));
    assert!(text.contains("from attached session"));
    assert!(!text.contains("local view"));
}

#[test]
fn skills_pane_local_fallback_when_detached() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_for_skills(&tmp);

    open_skills_pane_trusted(&mut app, &tmp);

    assert_eq!(app.async_actions.pending_count(), 0);
    let text = skills_text(&app);
    // Pre-attach inventory is explicitly unavailable — no local walk.
    assert!(text.contains("inventory unavailable until attached") || text.contains("unavailable"));
    assert!(!text.contains("local view"));
}

#[tokio::test]
async fn skills_pane_attached_failure_degrades_to_local() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_for_skills(&tmp);
    let (attached_request_tx, mut attached_request_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_attached_request_tx(attached_request_tx)));

    open_skills_pane_trusted(&mut app, &tmp);
    let attached = attached_request_rx.recv().await.unwrap();
    attached
        .response_tx
        .send(Err("not_attached".to_string()))
        .unwrap();

    drain_until_idle(&mut app).await;

    let text = skills_text(&app);
    // Failure surfaces the daemon error; no local discovery fallback.
    assert!(text.contains("not_attached"));
    assert!(!text.contains("local view"));
}

#[tokio::test]
async fn skills_pane_fetch_is_async_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_for_skills(&tmp);
    let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_attached_request_tx(attached_request_tx)));

    open_skills_pane_trusted(&mut app, &tmp);

    assert_eq!(
        app.async_actions.pending_kinds(),
        vec![AsyncActionKind::DaemonRpc("skills.list")]
    );
    assert_eq!(skills_text(&app), "Loading skills...");
}

#[tokio::test]
async fn skills_pane_stale_result_dropped() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_for_skills(&tmp);
    let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_attached_request_tx(attached_request_tx)));

    open_skills_pane_trusted(&mut app, &tmp);
    let stale_id = app.async_actions.pending_ids().pop().unwrap();
    let stale_generation = skills_generation(&app);
    app.agent_runner = None;
    open_skills_pane_trusted(&mut app, &tmp);

    app.apply_async_action_result(AsyncActionResult {
        id: stale_id,
        kind: AsyncActionKind::DaemonRpc("skills.list"),
        payload: Ok(AsyncActionPayload::Skills(SkillsPaneFetchResult {
            generation: stale_generation,
            source: SkillsPaneSource::Session,
            skills: Ok(vec![summary("stale-session", "old result", "/session")]),
            bundle: None,
        })),
    });

    let text = skills_text(&app);
    // Detached reopen shows unavailable; stale attached generation is dropped.
    assert!(text.contains("inventory unavailable until attached") || text.contains("unavailable"));
    assert!(!text.contains("stale-session"));
}
