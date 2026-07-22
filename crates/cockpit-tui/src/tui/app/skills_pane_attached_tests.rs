use super::{App, Overlay};
use crate::tui::agent_runner::{AgentRunner, AttachedRequest, ClientTasks, UsageCounts};
use crate::tui::async_action::{AsyncActionKind, AsyncActionPayload, AsyncActionResult};
use crate::tui::skills_pane::{SkillsPaneFetchResult, SkillsPaneSource};
use cockpit_core::daemon::proto::{Request, Response, SkillSummary};
use cockpit_core::engine::message::UserSubmission;
use std::fs;
use std::path::{Path, PathBuf};
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
    App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    )
}

fn write_skill(scan: &Path, dir: &str, name: &str, description: &str) {
    let skill_dir = scan.join(dir);
    fs::create_dir_all(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: {description}\n---\nBody\n"),
    )
    .unwrap();
}

fn runner_with_attached_request_tx(
    attached_request_tx: mpsc::Sender<AttachedRequest>,
) -> AgentRunner {
    let (input_tx, _input_rx) = mpsc::channel::<UserSubmission>(1);
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

    app.open_skills_pane();

    assert_eq!(
        app.async_actions.pending_kinds(),
        vec![AsyncActionKind::DaemonRpc("skills.list")]
    );
    let attached = attached_request_rx.recv().await.unwrap();
    match attached.request {
        Request::ListSkills { project_root } => {
            assert_eq!(project_root, tmp.path().to_string_lossy().into_owned());
        }
        other => panic!("unexpected request: {other:?}"),
    }
    attached
        .response_tx
        .send(Ok(Response::Skills {
            skills: vec![summary("session-only", "from attached session", "/session")],
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
    let scan = tmp.path().join("skills");
    write_skill(&scan, "local", "local-skill", "from local discovery");
    let mut app = app_for_skills(&tmp);

    app.open_skills_pane();

    assert_eq!(app.async_actions.pending_count(), 0);
    let text = skills_text(&app);
    assert!(text.contains("local view - session-specific activation unavailable"));
    assert!(text.contains("local-skill"));
    assert!(!text.contains("not_attached"));
}

#[tokio::test]
async fn skills_pane_attached_failure_degrades_to_local() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("skills");
    write_skill(&scan, "fallback", "fallback-skill", "from local fallback");
    let mut app = app_for_skills(&tmp);
    let (attached_request_tx, mut attached_request_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_attached_request_tx(attached_request_tx)));

    app.open_skills_pane();
    let attached = attached_request_rx.recv().await.unwrap();
    attached
        .response_tx
        .send(Err("not_attached".to_string()))
        .unwrap();

    drain_until_idle(&mut app).await;

    let text = skills_text(&app);
    assert!(text.contains("local view - session-specific activation unavailable"));
    assert!(text.contains("fallback-skill"));
    assert!(!text.contains("not_attached"));
    assert!(!text.contains("skills unavailable"));
}

#[tokio::test]
async fn skills_pane_fetch_is_async_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app_for_skills(&tmp);
    let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_attached_request_tx(attached_request_tx)));

    app.open_skills_pane();

    assert_eq!(
        app.async_actions.pending_kinds(),
        vec![AsyncActionKind::DaemonRpc("skills.list")]
    );
    assert_eq!(skills_text(&app), "Loading skills...");
}

#[tokio::test]
async fn skills_pane_stale_result_dropped() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("skills");
    write_skill(&scan, "fresh", "fresh-local", "new local pane");
    let mut app = app_for_skills(&tmp);
    let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_attached_request_tx(attached_request_tx)));

    app.open_skills_pane();
    let stale_id = app.async_actions.pending_ids().pop().unwrap();
    let stale_generation = skills_generation(&app);
    app.agent_runner = None;
    app.open_skills_pane();

    app.apply_async_action_result(AsyncActionResult {
        id: stale_id,
        kind: AsyncActionKind::DaemonRpc("skills.list"),
        payload: Ok(AsyncActionPayload::Skills(SkillsPaneFetchResult {
            generation: stale_generation,
            source: SkillsPaneSource::Session,
            skills: Ok(vec![summary("stale-session", "old result", "/session")]),
        })),
    });

    let text = skills_text(&app);
    assert!(text.contains("fresh-local"));
    assert!(!text.contains("stale-session"));
}
