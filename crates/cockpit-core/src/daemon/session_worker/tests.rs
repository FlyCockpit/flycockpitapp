use super::handle::*;
use super::helpers::*;
use super::lifecycle::*;
use super::run::*;
use super::*;
use crate::db::Db;
use std::io;
use std::sync::Mutex as StdMutex;
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct CaptureWriter(std::sync::Arc<StdMutex<Vec<u8>>>);

struct CaptureGuard(std::sync::Arc<StdMutex<Vec<u8>>>);

impl io::Write for CaptureGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureGuard;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureGuard(self.0.clone())
    }
}

fn text_delta(agent: &str, delta: &str) -> proto::Event {
    proto::Event::AssistantTextDelta {
        session_id: Uuid::nil(),
        agent: agent.to_string(),
        delta: delta.to_string(),
    }
}

fn reasoning_delta(agent: &str, delta: &str) -> proto::Event {
    proto::Event::ReasoningDelta {
        session_id: Uuid::nil(),
        agent: agent.to_string(),
        delta: delta.to_string(),
    }
}

#[test]
fn stream_delta_coalescer_merges_rapid_consecutive_text() {
    let mut c = StreamDeltaCoalescer::default();
    assert!(c.push(text_delta("builder", "hel")).is_empty());
    assert!(c.push(text_delta("builder", "lo")).is_empty());
    let flushed = c.flush();
    assert_eq!(flushed.len(), 1);
    assert!(matches!(
        &flushed[0],
        proto::Event::AssistantTextDelta { agent, delta, .. }
            if agent == "builder" && delta == "hello"
    ));
}

#[test]
fn stream_delta_coalescer_flushes_before_non_delta_event() {
    let mut c = StreamDeltaCoalescer::default();
    assert!(c.push(text_delta("builder", "a")).is_empty());
    let out = c.push(proto::Event::AgentIdle {
        session_id: Uuid::nil(),
        turn_id: None,
        reason: crate::engine::IdleReason::Completed,
    });
    assert_eq!(out.len(), 2);
    assert!(matches!(
        &out[0],
        proto::Event::AssistantTextDelta { delta, .. } if delta == "a"
    ));
    assert!(matches!(&out[1], proto::Event::AgentIdle { .. }));
}

#[test]
fn stream_delta_coalescer_keeps_agents_and_delta_kinds_separate() {
    let mut c = StreamDeltaCoalescer::default();
    assert!(c.push(text_delta("builder", "a")).is_empty());
    let out = c.push(text_delta("reviewer", "b"));
    assert_eq!(out.len(), 1, "agent change flushes prior stream");
    assert!(matches!(
        &out[0],
        proto::Event::AssistantTextDelta { agent, delta, .. }
            if agent == "builder" && delta == "a"
    ));
    let out = c.push(reasoning_delta("reviewer", "r"));
    assert_eq!(out.len(), 1, "kind change flushes prior stream");
    assert!(matches!(
        &out[0],
        proto::Event::AssistantTextDelta { agent, delta, .. }
            if agent == "reviewer" && delta == "b"
    ));
    let flushed = c.flush();
    assert!(matches!(
        &flushed[0],
        proto::Event::ReasoningDelta { agent, delta, .. }
            if agent == "reviewer" && delta == "r"
    ));
}

#[test]
fn stream_delta_coalescer_byte_cap_flushes_before_window() {
    let mut c = StreamDeltaCoalescer::default();
    assert!(c.push(text_delta("builder", "a")).is_empty());
    let big = "x".repeat(STREAM_DELTA_COALESCE_BYTE_CAP);
    let out = c.push(text_delta("builder", &big));
    assert_eq!(out.len(), 1);
    assert!(matches!(
        &out[0],
        proto::Event::AssistantTextDelta { delta, .. }
            if delta.len() == STREAM_DELTA_COALESCE_BYTE_CAP + 1
    ));
    assert!(!c.has_pending());
}

#[test]
fn stream_delta_coalescer_sets_flush_deadline_only_while_buffered() {
    let mut c = StreamDeltaCoalescer::default();
    assert!(c.deadline().is_none());
    assert!(c.push(text_delta("builder", "a")).is_empty());
    assert!(c.deadline().is_some());
    let _ = c.flush();
    assert!(c.deadline().is_none());
}

#[tokio::test(start_paused = true)]
async fn stream_delta_coalescer_timer_flushes_after_window() {
    let mut c = StreamDeltaCoalescer::default();
    assert!(c.push(text_delta("builder", "a")).is_empty());
    assert!(c.push(text_delta("builder", "b")).is_empty());

    let mut sleeper = Box::pin(tokio::time::sleep_until(c.deadline().unwrap()));
    tokio::time::advance(STREAM_DELTA_COALESCE_WINDOW - std::time::Duration::from_millis(1)).await;
    tokio::select! {
        _ = &mut sleeper => panic!("coalescing timer fired before the flush window elapsed"),
        _ = tokio::task::yield_now() => {}
    }

    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    sleeper.await;
    let flushed = c.flush();
    assert_eq!(flushed.len(), 1);
    assert!(matches!(
        &flushed[0],
        proto::Event::AssistantTextDelta { delta, .. } if delta == "ab"
    ));
}

fn capture_warn_log(f: impl FnOnce()) -> String {
    let bytes = std::sync::Arc::new(StdMutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::WARN)
        .with_ansi(false)
        .with_writer(CaptureWriter(bytes.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
}

#[test]
fn steer_side_channel_stores_raw_and_stamps_origin() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    session
        .db
        .upsert_task_delegation_job(
            session.id,
            "task-live",
            Some("fn-live"),
            "Build",
            None,
            &[crate::db::task_delegations::DelegationChildInit {
                label: "alpha",
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }],
        )
        .unwrap();
    let cfg = crate::config::extended::RedactConfig {
        denylist: vec!["secret-user-steer-token".to_string()],
        ..Default::default()
    };
    let table = RedactionTable::build(&cfg, tmp.path()).unwrap();

    let result = steer_delegation_side_channel(
        &session,
        &table,
        "task-live".to_string(),
        "alpha".to_string(),
        "please use secret-user-steer-token".to_string(),
        "local:tester".to_string(),
    );

    assert_eq!(result.status, proto::DelegationSteerStatus::Queued);
    assert_eq!(result.origin_principal.as_deref(), Some("local:tester"));
    assert!(result.scrubbed);
    let steers = session
        .db
        .drain_task_delegation_steers("task-live", "alpha")
        .unwrap();
    assert_eq!(steers.len(), 1);
    assert_eq!(steers[0].origin_principal, "local:tester");
    assert!(steers[0].body.contains("secret-user-steer-token"));
}

#[test]
fn steer_side_channel_rejects_non_running_child_without_enqueue() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    session
        .db
        .upsert_task_delegation_job(
            session.id,
            "task-done",
            Some("fn-done"),
            "Build",
            None,
            &[crate::db::task_delegations::DelegationChildInit {
                label: "default",
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }],
        )
        .unwrap();
    session
        .db
        .cancel_task_delegation_child("task-done", "default")
        .unwrap();

    let result = steer_delegation_side_channel(
        &session,
        &RedactionTable::empty(),
        "task-done".to_string(),
        "default".to_string(),
        "continue".to_string(),
        "local:tester".to_string(),
    );

    assert_eq!(result.status, proto::DelegationSteerStatus::NotSteerable);
    assert!(result.message.contains("cancelled"), "{result:?}");
    assert!(
        session
            .db
            .drain_task_delegation_steers("task-done", "default")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn turn_refresh_sends_rebuilt_redaction_table_to_driver() {
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(
        tmp.path().join(".env"),
        "SESSION_REFRESH_SECRET=worker-secret\n",
    )
    .unwrap();
    let session = Session::create(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
    )
    .unwrap();
    let (event_tx, _event_rx) = broadcast::channel(8);
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
    let (driver_tx, mut driver_rx) = mpsc::channel(1);
    let mut notified = HashSet::new();

    refresh_redaction_for_turn(
        &session,
        session.id,
        tmp.path(),
        crate::config::extended::RedactConfig::default(),
        &RedactionSourceOverrides::default(),
        &mut notified,
        &redaction,
        &event_tx,
        &driver_tx,
        &HashMap::new(),
    )
    .await;

    let crate::engine::driver::DriverControl::SetRedaction { table, .. } =
        driver_rx.recv().await.unwrap()
    else {
        panic!("unexpected driver control");
    };
    let scrubbed = table.scrub("worker-secret");
    assert!(!scrubbed.contains("worker-secret"));
    assert!(scrubbed.contains("REDACTED"));
    let persisted = session.persisted_redaction_table().unwrap().unwrap();
    assert!(!persisted.scrub("worker-secret").contains("worker-secret"));
}

fn persisted_notice_text(session: &Session) -> String {
    let events = session.db.list_session_events(session.id).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "notice");
    events[0].data["text"].as_str().unwrap().to_string()
}

#[test]
fn engine_notice_is_recorded_as_durable_session_event() {
    let session = Session::create(
        Db::open_in_memory().unwrap(),
        PathBuf::from("/proj"),
        "Build",
    )
    .unwrap();
    let (event_tx, _event_rx) = broadcast::channel(8);
    let table = Arc::new(RedactionTable::empty());
    let mut events = proto::turn_event_to_proto(
        TurnEvent::Notice {
            text: "Engine notice text.".to_string(),
        },
        session.id,
    );
    assert_eq!(events.len(), 1);

    send_session_event(
        &session,
        &event_tx,
        &table,
        events.pop().unwrap(),
        NoticeSource::EngineTurn,
    );

    let rows = session.db.list_session_events(session.id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "notice");
    assert_eq!(rows[0].data["text"], "Engine notice text.");
    assert_eq!(rows[0].data["source"], "engine_turn");
    assert_eq!(rows[0].data["severity"], "info");
}

#[test]
fn notice_is_recorded_exactly_once_across_both_paths() {
    let session = Session::create(
        Db::open_in_memory().unwrap(),
        PathBuf::from("/proj"),
        "Build",
    )
    .unwrap();
    let (event_tx, _event_rx) = broadcast::channel(8);
    let table = Arc::new(RedactionTable::empty());
    let events = proto::turn_event_to_proto(
        TurnEvent::Notice {
            text: "Single notice.".to_string(),
        },
        session.id,
    );

    for event in events {
        send_session_event(&session, &event_tx, &table, event, NoticeSource::EngineTurn);
    }

    let rows = session.db.list_session_events(session.id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "notice");
    assert_eq!(rows[0].data["text"], "Single notice.");
}

#[test]
fn daemon_direct_notice_is_recorded_as_durable_session_event() {
    let session = Session::create(
        Db::open_in_memory().unwrap(),
        PathBuf::from("/proj"),
        "Build",
    )
    .unwrap();
    let (event_tx, _event_rx) = broadcast::channel(8);
    let table = Arc::new(RedactionTable::empty());

    send_session_event(
        &session,
        &event_tx,
        &table,
        proto::Event::Notice {
            session_id: session.id,
            text: "Daemon warning.".to_string(),
        },
        NoticeSource::DaemonDirect,
    );

    let rows = session.db.list_session_events(session.id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "notice");
    assert_eq!(rows[0].data["text"], "Daemon warning.");
    assert_eq!(rows[0].data["source"], "daemon_direct");
    assert_eq!(rows[0].data["severity"], "warning");
}

#[test]
fn sessionless_notice_is_dropped_without_error() {
    let table = RedactionTable::empty();
    record_notice_event_with_agent(
        None,
        None,
        &table,
        &proto::Event::Notice {
            session_id: Uuid::new_v4(),
            text: "Sessionless notice.".to_string(),
        },
        NoticeSource::DaemonDirect,
    );
}

#[test]
fn recorded_notice_text_is_redacted() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = crate::config::extended::RedactConfig {
        denylist: vec!["session-secret-token".to_string()],
        ..Default::default()
    };
    let table = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
    let session = Session::create(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
    )
    .unwrap();
    let (event_tx, _event_rx) = broadcast::channel(8);

    send_session_event(
        &session,
        &event_tx,
        &table,
        proto::Event::Notice {
            session_id: session.id,
            text: "Provider returned session-secret-token".to_string(),
        },
        NoticeSource::DaemonDirect,
    );

    let text = persisted_notice_text(&session);
    assert!(!text.contains("session-secret-token"));
    assert!(text.contains("REDACTED"));
}

#[test]
fn session_driver_failed_event_is_latched() {
    let (event_tx, mut event_rx) = broadcast::channel(8);
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
    let session_id = Uuid::new_v4();
    let mut driver_failed = false;

    emit_session_driver_failed_once(
        &event_tx,
        &redaction,
        session_id,
        &mut driver_failed,
        "first failure".to_string(),
    );
    emit_session_driver_failed_once(
        &event_tx,
        &redaction,
        session_id,
        &mut driver_failed,
        "second failure".to_string(),
    );

    let event = event_rx.try_recv().unwrap();
    assert!(matches!(
        event.event,
        proto::Event::SessionDriverFailed { session_id: id, error, .. }
            if id == session_id && error == "first failure"
    ));
    assert!(
        event_rx.try_recv().is_err(),
        "failure event is emitted once"
    );
}

#[tokio::test]
async fn driver_join_outcome_observes_panics() {
    let handle = tokio::spawn(async {
        panic!("driver panic for test");
        #[allow(unreachable_code)]
        DriverOutcome::Ok
    });

    let outcome = driver_join_outcome(handle.await);

    assert!(matches!(outcome, DriverOutcome::Panicked(error) if error == "driver panic for test"));
}

#[tokio::test]
async fn absent_scheduler_is_not_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let locks = Arc::new(LockManager::from_db(db.clone()).unwrap());
    let session = Arc::new(Session::create(db, tmp.path().to_path_buf(), "Build").unwrap());
    let providers = lmstudio_test_providers();
    let redact = Arc::new(RedactionTable::empty());
    let model =
        Arc::new(crate::engine::model::Model::from_config(&providers, redact.clone()).unwrap());
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.sandbox.default_mode = crate::config::sandbox_mode::SandboxMode::Off;
    let trust_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::TrustRoot {
            opened_path: tmp.path().to_path_buf(),
            root: tmp.path().to_path_buf(),
            kind: crate::config::trust::TrustRootKind::Directory,
        },
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };

    let (handle, join) = spawn(
        session,
        locks,
        redact,
        model,
        None,
        None,
        tmp.path().to_path_buf(),
        false,
        &extended,
        Arc::new(crate::daemon::lsp::LspManager::new()),
        None,
        Arc::new(StdMutex::new(None)),
        None,
        trust_policy,
        None,
        EnvSnapshot::new(
            crate::env_snapshot::EnvSnapshotSource::DaemonStart,
            Default::default(),
        ),
        SessionConfigSnapshot::new(0, providers, extended.clone()),
    );

    handle
        .send_work(SessionWork::Shutdown {
            pause_for_resume: false,
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), join)
        .await
        .expect("worker shuts down")
        .expect("worker task does not panic");
}

/// An [`ExtendedConfig`] pinning `defaultPrimaryAgent` + the
/// experimental flag, for the gate tests.
fn cfg_with(
    default_primary: crate::config::extended::DefaultPrimaryAgent,
    experimental: bool,
) -> crate::config::extended::ExtendedConfig {
    crate::config::extended::ExtendedConfig {
        default_primary_agent: default_primary,
        experimental_mode: experimental,
        ..Default::default()
    }
}

struct IsolatedCockpitEnv {
    _guard: crate::test_env::TestEnvGuard,
}

impl IsolatedCockpitEnv {
    fn new(root: &std::path::Path) -> Self {
        Self {
            _guard: crate::test_env::TestEnvGuard::isolate_cockpit_home_at(root),
        }
    }
}

fn write_model_config(cwd: &std::path::Path) {
    let cockpit_dir = cwd.join(".cockpit");
    std::fs::create_dir_all(cockpit_dir.join("providers")).unwrap();
    std::fs::write(
        cockpit_dir.join("config.json"),
        r#"{"active_model":{"provider":"lmstudio","model":"session-model"}}"#,
    )
    .unwrap();
    std::fs::write(
        cockpit_dir.join("providers/lmstudio.json"),
        r#"{
              "url": "http://localhost:1/v1",
              "models": [
                {"id": "session-model"},
                {"id": "assistant-model"}
              ]
            }"#,
    )
    .unwrap();
}

fn lmstudio_test_providers() -> crate::config::providers::ProvidersConfig {
    use crate::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry, ProvidersConfig};

    let mut providers = std::collections::BTreeMap::new();
    providers.insert(
        "lmstudio".to_string(),
        ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            models: vec![
                ModelEntry {
                    id: "session-model".to_string(),
                    ..ModelEntry::default()
                },
                ModelEntry {
                    id: "assistant-model".to_string(),
                    ..ModelEntry::default()
                },
            ],
            ..ProviderEntry::default()
        },
    );
    ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "lmstudio".to_string(),
            model: "session-model".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..ProvidersConfig::default()
    }
}

fn test_spawn_args(cwd: &std::path::Path) -> crate::engine::builtin::SpawnArgs {
    use std::sync::Arc;

    let providers = lmstudio_test_providers();
    let model = Arc::new(
        crate::engine::model::Model::from_config(
            &providers,
            Arc::new(crate::redact::RedactionTable::empty()),
        )
        .unwrap(),
    );
    crate::engine::builtin::SpawnArgs {
        model,
        params: crate::engine::model::ModelParams::default(),
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        cwd: cwd.to_path_buf(),
        config: crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd),
        session_short_id: "abc123".to_string(),
        assistant_identity_prefix: None,
        model_system_prompt_snapshot: Arc::new(
            crate::model_system_prompt::ModelSystemPromptSnapshot::empty(),
        ),
        interactive: true,
        llm_mode: crate::config::extended::LlmMode::default(),
        model_override: None,
        delegation_model: None,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        swarm_depth: 0,
        swarm_max_depth: crate::config::extended::DEFAULT_SWARM_MAX_DEPTH,
        granted_tools: Vec::new(),
    }
}

#[test]
fn initial_active_agent_gates_default_to_build_when_off() {
    use crate::config::extended::DefaultPrimaryAgent as D;
    // Off: a gated configured default (Auto/Plan) resolves to Build.
    assert_eq!(initial_active_agent(&cfg_with(D::Auto, false)), "Build");
    assert_eq!(initial_active_agent(&cfg_with(D::Plan, false)), "Build");
    // Off: Build is honored (not gated).
    assert_eq!(initial_active_agent(&cfg_with(D::Build, false)), "Build");
    // On: the configured default is honored.
    assert_eq!(initial_active_agent(&cfg_with(D::Auto, true)), "Auto");
    assert_eq!(initial_active_agent(&cfg_with(D::Plan, true)), "Plan");
}

#[test]
fn seed_tool_drain_failure_warns_with_session_id_without_payload() {
    let session_id = Uuid::new_v4();
    let log = capture_warn_log(|| {
        let error = anyhow::anyhow!("db unavailable");
        log_seed_tool_drain_failed(session_id, &error);
    });

    assert!(log.contains(&session_id.to_string()));
    assert!(log.contains("seed-tool replay skipped"));
    assert!(log.contains("db unavailable"));
    assert!(!log.contains("prompt text"));
    assert!(!log.contains("tool output"));
}

#[test]
fn resolve_root_agent_stale_gated_session_falls_back_to_build() {
    use crate::config::extended::DefaultPrimaryAgent as D;
    let db = crate::db::Db::open_in_memory().unwrap();
    // A session persisted on a gated primary (`Plan`), experimental off →
    // loads on `Build`. (`Swarm` is not resume-eligible per
    // the active-agent filter, so they degrade via the default path —
    // also `Build` when off.)
    let row = db.create_session("proj", "/proj", "Plan").unwrap();
    assert_eq!(
        resolve_root_agent(row.session_id, &db, &cfg_with(D::Auto, false)),
        "Build"
    );
    // Same persisted session, experimental on → the stored value stands.
    assert_eq!(
        resolve_root_agent(row.session_id, &db, &cfg_with(D::Auto, true)),
        "Plan"
    );
}

#[test]
fn resolve_root_agent_assistant_session_bypasses_primary_allowlist() {
    use crate::config::extended::DefaultPrimaryAgent as D;
    let db = crate::db::Db::open_in_memory().unwrap();
    db.upsert_assistant("helper-bot", "/tmp/helper-bot", "{}", "hash")
        .unwrap();
    let row = db
        .create_assistant_session("proj", "/proj", "helper-bot", "helper-bot")
        .unwrap();

    assert_eq!(
        resolve_root_agent(row.session_id, &db, &cfg_with(D::Auto, false)),
        "helper-bot"
    );
}

#[test]
fn resolve_root_agent_deleted_assistant_falls_back_to_default_primary() {
    use crate::config::extended::DefaultPrimaryAgent as D;
    let db = crate::db::Db::open_in_memory().unwrap();
    let row = db
        .create_assistant_session("proj", "/proj", "missing-bot", "missing-bot")
        .unwrap();

    assert_eq!(
        resolve_root_agent(row.session_id, &db, &cfg_with(D::Build, true)),
        "Build"
    );
}

#[test]
fn assistant_session_root_agent_loads_assistant_definition() {
    use crate::agents::AgentMode;
    use crate::assistants::{CreateAssistantSpec, create_assistant};
    use crate::config::extended::DefaultPrimaryAgent as D;

    let tmp = tempfile::tempdir().unwrap();
    let _env = IsolatedCockpitEnv::new(tmp.path());
    let cwd = tmp.path().join("project");
    std::fs::create_dir_all(&cwd).unwrap();
    write_model_config(&cwd);
    let db = Db::open_default().unwrap();
    create_assistant(
        &db,
        CreateAssistantSpec {
            name: "helper-bot".to_string(),
            description: "Helper bot".to_string(),
            mode: AgentMode::Primary,
            tools: Some(vec!["read".to_string()]),
            tool_tiers: std::collections::BTreeMap::new(),
            model: Some("lmstudio/assistant-model".to_string()),
            prompt: "ASSISTANT_DEFINITION_MARKER".to_string(),
            home_dir: tmp.path().join("assistants/helper-bot"),
        },
    )
    .unwrap();
    let row = db
        .create_assistant_session("proj", cwd.to_str().unwrap(), "helper-bot", "helper-bot")
        .unwrap();

    let root_agent_name = resolve_root_agent(row.session_id, &db, &cfg_with(D::Auto, false));
    let root = crate::engine::builtin::load(&root_agent_name, &test_spawn_args(&cwd)).unwrap();

    assert_eq!(root.name, "helper-bot");
    assert!(root.role_prompt.contains("ASSISTANT_DEFINITION_MARKER"));
    assert!(root.system.contains("ASSISTANT_DEFINITION_MARKER"));
    assert_eq!(root.model.provider_id(), "lmstudio");
    assert_eq!(root.model.model_id_ref(), "assistant-model");
    assert!(root.tools.names().contains(&"read"));
}

#[test]
fn sandbox_default_precedence_daemon_wins() {
    use crate::tools::sandbox_mode::SandboxMode;

    // (a) daemon `--no-sandbox` -> OFF regardless of the client flag.
    assert_eq!(
        resolve_sandbox_default_with(true, false, SandboxMode::Sandbox),
        SandboxMode::Off
    );
    assert_eq!(
        resolve_sandbox_default_with(true, true, SandboxMode::Container),
        SandboxMode::Off
    );
}

#[test]
fn sandbox_default_precedence_client_then_on() {
    use crate::tools::sandbox_mode::SandboxMode;

    // (b) no daemon flag, client `--no-sandbox` -> OFF.
    assert_eq!(
        resolve_sandbox_default_with(false, true, SandboxMode::Container),
        SandboxMode::Off
    );
    // (c) neither flag -> ON.
    assert_eq!(
        resolve_sandbox_default_with(false, false, SandboxMode::Sandbox),
        SandboxMode::Sandbox
    );
}

/// The concurrent-write-during-plan warning fires once per plan episode per
/// session, re-arms on a different plan, and is mode-aware
/// (`plan-concurrent-build-and-merge.md`).
#[test]
fn lifecycle_turn_id_maps_to_proto_events() {
    let sid = Uuid::new_v4();
    let out = proto::turn_event_to_proto(
        TurnEvent::ThinkingStarted {
            agent: "Build".to_string(),
            turn_id: Some("turn-1".to_string()),
        },
        sid,
    );
    match out.as_slice() {
        [
            proto::Event::ThinkingStarted {
                session_id,
                agent,
                turn_id,
            },
        ] => {
            assert_eq!(*session_id, sid);
            assert_eq!(agent, "Build");
            assert_eq!(turn_id.as_deref(), Some("turn-1"));
        }
        other => panic!("expected one ThinkingStarted, got {other:?}"),
    }

    let out = proto::turn_event_to_proto(
        TurnEvent::AgentIdle {
            turn_id: Some("turn-1".to_string()),
            reason: crate::engine::IdleReason::Completed,
        },
        sid,
    );
    match out.as_slice() {
        [
            proto::Event::AgentIdle {
                session_id,
                turn_id,
                reason,
            },
        ] => {
            assert_eq!(*session_id, sid);
            assert_eq!(turn_id.as_deref(), Some("turn-1"));
            assert_eq!(reason, &crate::engine::IdleReason::Completed);
        }
        other => panic!("expected one AgentIdle, got {other:?}"),
    }
}

#[test]
fn foreground_input_target_maps_to_proto_event() {
    let sid = Uuid::new_v4();
    let out = proto::turn_event_to_proto(
        TurnEvent::ForegroundInputTarget {
            target: crate::engine::message::QueueTarget::child("explore", 1, "call-1", "default"),
        },
        sid,
    );

    match out.as_slice() {
        [proto::Event::ForegroundInputTarget { session_id, target }] => {
            assert_eq!(*session_id, sid);
            assert_eq!(target.id, "task:call-1:default");
            assert_eq!(target.agent, "explore");
            assert_eq!(target.depth, 1);
            assert_eq!(target.task_call_id.as_deref(), Some("call-1"));
        }
        other => panic!("expected one ForegroundInputTarget, got {other:?}"),
    }
}

#[test]
fn nested_turn_event_maps_to_wrapped_proto_event() {
    let sid = Uuid::new_v4();
    let out = proto::turn_event_to_proto(
        TurnEvent::NestedTurn {
            task_call_id: "task-1".into(),
            label: "default".into(),
            parent_task_call_id: Some("parent-task".into()),
            inner: Box::new(TurnEvent::AssistantTextDelta {
                agent: "Explore".into(),
                delta: "hello".into(),
            }),
        },
        sid,
    );
    match out.as_slice() {
        [
            proto::Event::NestedTurn {
                session_id,
                task_call_id,
                label,
                parent_task_call_id,
                inner,
            },
        ] => {
            assert_eq!(*session_id, sid);
            assert_eq!(task_call_id, "task-1");
            assert_eq!(label, "default");
            assert_eq!(parent_task_call_id.as_deref(), Some("parent-task"));
            match inner.as_ref() {
                proto::Event::AssistantTextDelta {
                    session_id,
                    agent,
                    delta,
                } => {
                    assert_eq!(*session_id, sid);
                    assert_eq!(agent, "Explore");
                    assert_eq!(delta, "hello");
                }
                other => panic!("expected wrapped AssistantTextDelta, got {other:?}"),
            }
        }
        other => panic!("expected one NestedTurn, got {other:?}"),
    }
}

#[test]
fn live_foreground_snapshot_tracks_nested_active_subagent() {
    let foreground = Arc::new(Mutex::new(LiveForegroundState::new("Build".to_string())));
    let target = Arc::new(Mutex::new(crate::engine::message::QueueTarget::root(
        "Build",
    )));

    update_live_foreground(
        &foreground,
        &target,
        &TurnEvent::SubagentSpawned {
            parent: "Build".into(),
            child: "builder".into(),
            task_call_id: "task-1".into(),
            label: "default".into(),
            prompt: "build it".into(),
            requested_cwd: None,
            resolved_cwd: None,
            trusted_only: false,
            model_trusted: false,
            routing: serde_json::json!({}),
        },
    );
    update_live_foreground(
        &foreground,
        &target,
        &TurnEvent::ForegroundInputTarget {
            target: crate::engine::message::QueueTarget::child("builder", 1, "task-1", "default"),
        },
    );
    update_live_foreground(
        &foreground,
        &target,
        &TurnEvent::SubagentSpawned {
            parent: "builder".into(),
            child: "bee".into(),
            task_call_id: "task-2".into(),
            label: "default".into(),
            prompt: "continue".into(),
            requested_cwd: None,
            resolved_cwd: None,
            trusted_only: false,
            model_trusted: false,
            routing: serde_json::json!({}),
        },
    );

    let snap = foreground.lock().unwrap().snapshot();
    assert_eq!(snap.active_agent_path, ["Build", "builder", "bee"]);
    assert_eq!(snap.foreground_target.agent, "bee");
    assert_eq!(snap.foreground_target.depth, 2);
    let active = snap.active_subagent.expect("active subagent descriptor");
    assert_eq!(active.parent, "builder");
    assert_eq!(active.child, "bee");
    assert_eq!(active.task_call_id, "task-2");

    update_live_foreground(
        &foreground,
        &target,
        &TurnEvent::SubagentReport {
            agent: "bee".into(),
            task_call_id: "task-2".into(),
            label: "default".into(),
            report: "done".into(),
            failed: false,
            trusted_only: false,
            model_trusted: false,
            routing: serde_json::json!({}),
        },
    );
    let snap = foreground.lock().unwrap().snapshot();
    assert_eq!(snap.active_agent_path, ["Build", "builder"]);
    assert_eq!(snap.foreground_target.agent, "builder");
    assert_eq!(snap.foreground_target.depth, 1);
    assert_eq!(
        snap.active_subagent.as_ref().map(|sub| sub.child.as_str()),
        Some("builder")
    );
}

#[test]
fn routing_amend_does_not_alter_foreground_state() {
    let foreground = Arc::new(Mutex::new(LiveForegroundState::new("Build".to_string())));
    let target = Arc::new(Mutex::new(crate::engine::message::QueueTarget::root(
        "Build",
    )));
    let spawn = TurnEvent::SubagentSpawned {
        parent: "Build".into(),
        child: "explore".into(),
        task_call_id: "task-1".into(),
        label: "default".into(),
        prompt: "look around".into(),
        requested_cwd: None,
        resolved_cwd: None,
        trusted_only: false,
        model_trusted: false,
        routing: serde_json::json!({ "resolved_model": "parent-model" }),
    };
    let amend = TurnEvent::SubagentRouting {
        task_call_id: "task-1".into(),
        label: "default".into(),
        child: "explore".into(),
        provider: "lmstudio".into(),
        model: "child-model".into(),
        trusted_only: true,
        model_trusted: true,
        routing: serde_json::json!({ "resolved_model": "child-model" }),
    };
    let report = TurnEvent::SubagentReport {
        agent: "explore".into(),
        task_call_id: "task-1".into(),
        label: "default".into(),
        report: "done".into(),
        failed: false,
        trusted_only: true,
        model_trusted: true,
        routing: serde_json::json!({ "resolved_model": "child-model" }),
    };

    update_live_foreground(&foreground, &target, &spawn);
    let after_spawn = foreground.lock().unwrap().snapshot();
    update_live_foreground(&foreground, &target, &amend);
    let after_amend = foreground.lock().unwrap().snapshot();
    assert_eq!(after_amend.active_agent_path, after_spawn.active_agent_path);
    assert_eq!(after_amend.active_subagent, after_spawn.active_subagent);
    assert_eq!(after_amend.foreground_target, after_spawn.foreground_target);

    update_live_foreground(&foreground, &target, &report);
    let after_report = foreground.lock().unwrap().snapshot();
    assert_eq!(after_report.active_agent_path, ["Build"]);
    assert!(after_report.active_subagent.is_none());
    assert_eq!(after_report.foreground_target.agent, "Build");
    assert_eq!(after_report.foreground_target.depth, 0);
}

/// §6.5: the sandbox-unavailable `TurnEvent` maps to the wire broadcast
/// carrying the session_id + the verbatim diagnosed remedy.
#[test]
fn sandbox_unavailable_maps_to_broadcast_with_remedy() {
    let sid = Uuid::new_v4();
    let remedy = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
             `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement"
        .to_string();
    let fix_command = "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0";
    let out = proto::turn_event_to_proto(
        TurnEvent::SandboxUnavailable {
            remedy: remedy.clone(),
            fix_command: Some(fix_command.to_string()),
        },
        sid,
    );
    match out.as_slice() {
        [
            proto::Event::SandboxUnavailable {
                session_id,
                remedy: r,
                fix_command: got_fix_command,
            },
        ] => {
            assert_eq!(*session_id, sid);
            assert_eq!(r, &remedy);
            assert_eq!(got_fix_command.as_deref(), Some(fix_command));
            // The user-facing remedy names the exact host command.
            assert!(r.contains("sudo sysctl"));
        }
        other => panic!("expected one SandboxUnavailable, got {other:?}"),
    }
}

#[test]
fn command_capability_unavailable_maps_to_broadcast_with_fix_command() {
    let sid = Uuid::new_v4();
    let text = "Required command capability unavailable: `demo` missing for `tool`.";
    let fix_command = "sudo apt-get install demo";
    let out = proto::turn_event_to_proto(
        TurnEvent::CommandCapabilityUnavailable {
            text: text.to_string(),
            fix_command: Some(fix_command.to_string()),
        },
        sid,
    );
    match out.as_slice() {
        [
            proto::Event::CommandCapabilityUnavailable {
                session_id,
                text: got_text,
                fix_command: got_fix_command,
            },
        ] => {
            assert_eq!(*session_id, sid);
            assert_eq!(got_text, text);
            assert_eq!(got_fix_command.as_deref(), Some(fix_command));
        }
        other => panic!("expected one CommandCapabilityUnavailable, got {other:?}"),
    }
}

/// Reattach hydration: once the daemon has diagnosed sandbox startup as
/// unavailable, a later client attach re-broadcasts the remembered notice
/// with the structured fix command without waiting for another `bash` call.
#[tokio::test]
async fn sandbox_unavailable_hydration_rebroadcasts_remembered_notice() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    session.set_sandbox_mode(crate::tools::sandbox_mode::SandboxMode::Sandbox);
    let locks = Arc::new(LockManager::in_memory(db));
    let handle = SessionWorkerHandle::test_handle(Arc::new(session), locks);
    let remedy = "sandbox unavailable because AppArmor blocks user namespaces".to_string();
    let fix_command = "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0".to_string();
    *handle
        .sandbox_unavailable_notice
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(SandboxUnavailableNotice {
        remedy: remedy.clone(),
        fix_command: Some(fix_command.clone()),
    });

    let mut rx = handle.subscribe();
    handle.broadcast_sandbox_unavailable_or_probe();

    let envelope = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("sandbox notice broadcast")
        .expect("event envelope");
    match envelope.event {
        proto::Event::SandboxUnavailable {
            session_id,
            remedy: got_remedy,
            fix_command: got_fix_command,
        } => {
            assert_eq!(session_id, handle.session_id);
            assert_eq!(got_remedy, remedy);
            assert_eq!(got_fix_command.as_deref(), Some(fix_command.as_str()));
        }
        other => panic!("expected SandboxUnavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn active_interrupt_hydration_rebroadcasts_with_rehydration_reason() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    let session_id = session.id;
    let set = proto::InterruptQuestionSet {
        questions: vec![proto::InterruptQuestion::Single {
            prompt: "Proceed?".to_string(),
            options: vec![proto::InterruptOption {
                id: "yes".to_string(),
                label: "Yes".to_string(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        }],
    };
    let interrupt_id = db
        .raise_interrupt_questions(session_id, "Build", "context", &set)
        .unwrap();
    let _queued = db
        .raise_interrupt_questions(session_id, "Build", "queued", &set)
        .unwrap();
    let locks = Arc::new(LockManager::in_memory(db));
    let handle = SessionWorkerHandle::test_handle(Arc::new(session), locks);

    let mut rx = handle.subscribe();
    handle.broadcast_active_interrupt();

    let envelope = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("active interrupt broadcast")
        .expect("event envelope");
    match envelope.event {
        proto::Event::InterruptRaised {
            session_id: got_session_id,
            interrupt_id: got_interrupt_id,
            description,
            pending_count,
            reason,
            ..
        } => {
            assert_eq!(got_session_id, session_id);
            assert_eq!(got_interrupt_id, interrupt_id);
            assert_eq!(description, "context");
            assert_eq!(pending_count, 1);
            assert_eq!(reason, proto::InterruptRaiseReason::Rehydration);
        }
        other => panic!("expected InterruptRaised, got {other:?}"),
    }
}

#[test]
fn shutdown_activity_snapshot_counts_open_and_parked_interrupts_as_pending_paused_work() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    let session_id = session.id;
    let set = proto::InterruptQuestionSet {
        questions: vec![proto::InterruptQuestion::Single {
            prompt: "Proceed?".to_string(),
            options: vec![proto::InterruptOption {
                id: "yes".to_string(),
                label: "Yes".to_string(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        }],
    };
    let open = db
        .raise_interrupt_questions(session_id, "Build", "open", &set)
        .unwrap();
    let parked = db
        .raise_interrupt_questions(session_id, "Build", "parked", &set)
        .unwrap();
    assert!(db.park_interrupt(parked).unwrap());

    let live = LiveState::default();
    let interrupts = crate::engine::interrupt::InterruptHub::detached();
    let (active, pending_tool_count) =
        shutdown_activity_snapshot(&session, session_id, &interrupts, &live);

    assert!(active, "blocked-only sessions must be paused on shutdown");
    assert_eq!(
        pending_tool_count, 2,
        "paused row count must include both open and already-parked interrupts"
    );
    assert_eq!(db.list_open_interrupts(session_id).unwrap().len(), 2);
    assert!(db.get_interrupt(open).unwrap().is_some());
}

/// §6.5 de-dupe: the latch fires the broadcast exactly once per condition.
/// Two failed `bash` calls (two `SandboxUnavailable` events) → one forward;
/// `set_sandbox` re-arms it (clearing the latch) so a renewed condition
/// after a `/sandbox` toggle can surface a fresh notice.
#[test]
fn sandbox_unavailable_dedupes_per_session() {
    let armed = AtomicBool::new(false);
    // First failed bash → forward.
    assert!(forward_sandbox_unavailable(&armed));
    // Second (and any further) failed bash in the same condition → drop.
    assert!(!forward_sandbox_unavailable(&armed));
    assert!(!forward_sandbox_unavailable(&armed));
    // `/sandbox` toggle re-arms (the latch the handle clears).
    armed.store(false, Ordering::SeqCst);
    // A renewed unavailable condition surfaces once more, then de-dupes.
    assert!(forward_sandbox_unavailable(&armed));
    assert!(!forward_sandbox_unavailable(&armed));
}

// ── Session-detach lock release edges (`session-detach-lock-release.md`) ──

use std::sync::atomic::AtomicUsize;

/// The detach edge fires only on the LAST detach (count 1→0) while idle.
#[test]
fn detach_should_release_only_on_last_detach_while_idle() {
    // Last detach (1→0), idle → release.
    assert!(detach_should_release(1, false));
    // Last detach but mid-turn → do NOT release.
    assert!(!detach_should_release(1, true));
    // Not the last client (2→1) → do NOT release, idle or not.
    assert!(!detach_should_release(2, false));
    assert!(!detach_should_release(2, true));
    // No clients to begin with → nothing.
    assert!(!detach_should_release(0, false));
}

/// Build a guard with injected state, bypassing the full worker `spawn`.
fn test_guard(
    counter: Arc<AtomicUsize>,
    session_id: Uuid,
    locks: Arc<LockManager>,
    live: Arc<LiveState>,
) -> InteractiveClientGuard {
    counter.fetch_add(1, Ordering::SeqCst);
    InteractiveClientGuard {
        counter,
        session_id,
        locks,
        live,
    }
}

async fn wait_until<F>(mut predicate: F)
where
    F: FnMut() -> bool,
{
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !predicate() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition became true");
}

/// Dropping the LAST interactive guard while the session is idle releases
/// the session's locks (the detach edge), and a blocked cross-session
/// waiter would be woken (the release calls `notify_waiters`).
#[tokio::test]
async fn last_detach_while_idle_releases_locks() {
    let tmp = tempfile::TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "x").unwrap();
    let db = Db::open_in_memory().unwrap();
    let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).unwrap();

    let counter = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(LiveState::default()); // not processing = idle
    let guard = test_guard(counter.clone(), sid, locks.clone(), live);
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    drop(guard); // last detach, idle → release
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert!(
        locks.holder(&p).is_some(),
        "drop must only schedule cleanup, not hash/release inline"
    );
    wait_until(|| locks.holder(&p).is_none()).await;
    assert!(
        locks.holder(&p).is_none(),
        "scheduled idle last-detach cleanup must release the session's lock"
    );
}

#[tokio::test]
async fn quick_reattach_skips_scheduled_unattended_release() {
    let tmp = tempfile::TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "x").unwrap();
    let db = Db::open_in_memory().unwrap();
    let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).unwrap();

    let counter = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(LiveState::default());
    let guard = test_guard(counter.clone(), sid, locks.clone(), live.clone());
    drop(guard);
    let _reattached = test_guard(counter.clone(), sid, locks.clone(), live);

    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        locks.holder(&p).map(|(_, a)| a).as_deref(),
        Some("builder"),
        "scheduled cleanup must skip when a client reattaches"
    );
}

/// A mid-turn detach (the agent is still processing) does NOT release; the
/// idle backstop does the release once the turn ends.
#[tokio::test]
async fn mid_turn_detach_keeps_locks_then_idle_releases() {
    let tmp = tempfile::TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "x").unwrap();
    let db = Db::open_in_memory().unwrap();
    let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).unwrap();

    let counter = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(LiveState::default());
    live.processing.store(true, Ordering::SeqCst); // mid-turn
    let guard = test_guard(counter.clone(), sid, locks.clone(), live.clone());

    drop(guard); // last detach, but mid-turn → NO release
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert!(
        locks.holder(&p).is_some(),
        "mid-turn detach must NOT release the lock"
    );

    // Turn ends → the AgentIdle edge (count already zero) releases. The
    // forward seam runs this exact branch; assert its decision + effect.
    live.processing.store(false, Ordering::SeqCst);
    if counter.load(Ordering::SeqCst) == 0 {
        schedule_session_locks_unattended(
            locks.clone(),
            counter.clone(),
            live.clone(),
            sid,
            "test idle edge",
        );
    }
    wait_until(|| locks.holder(&p).is_none()).await;
    assert!(
        locks.holder(&p).is_none(),
        "the idle edge releases the lock the mid-turn detach left held"
    );
}

/// Multi-attach: a second guard means the first detach (2→1) releases
/// nothing; only the last detach (1→0) does.
#[tokio::test]
async fn multi_attach_releases_only_on_last_detach() {
    let tmp = tempfile::TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "x").unwrap();
    let db = Db::open_in_memory().unwrap();
    let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).unwrap();

    let counter = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(LiveState::default());
    let g1 = test_guard(counter.clone(), sid, locks.clone(), live.clone());
    let g2 = test_guard(counter.clone(), sid, locks.clone(), live.clone());
    assert_eq!(counter.load(Ordering::SeqCst), 2);

    drop(g1); // 2→1: NOT the last detach → no release
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert!(
        locks.holder(&p).is_some(),
        "a non-last detach must not release"
    );

    drop(g2); // 1→0: last detach, idle → release
    wait_until(|| locks.holder(&p).is_none()).await;
    assert!(
        locks.holder(&p).is_none(),
        "the last detach releases the session's lock"
    );
}

fn provider_snapshot_config() -> crate::config::providers::ProvidersConfig {
    use crate::config::providers::{
        ActiveModelRef, HeaderSpec, ModelEntry, ProviderEntry, ProviderModelRef,
    };
    let mut providers = std::collections::BTreeMap::new();
    providers.insert(
        "openai".to_string(),
        ProviderEntry {
            name: Some("OpenAI".to_string()),
            url: "https://api.openai.example/v1".to_string(),
            headers: vec![HeaderSpec {
                name: "Authorization".to_string(),
                value: "Bearer sk-session-secret".to_string(),
            }],
            credential_ref: Some("openai-oauth".to_string()),
            mode: Some(crate::config::extended::LlmMode::Normal),
            models: vec![ModelEntry {
                id: "gpt-test".to_string(),
                name: Some("GPT Test".to_string()),
                context_length: Some(128_000),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let mut category_defaults = std::collections::BTreeMap::new();
    category_defaults.insert(
        "smart_code".to_string(),
        ProviderModelRef {
            provider: "openai".to_string(),
            model: "gpt-test".to_string(),
        },
    );
    crate::config::providers::ProvidersConfig {
        providers,
        category_defaults,
        active_model: Some(ActiveModelRef {
            provider: "openai".to_string(),
            model: "gpt-test".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..crate::config::providers::ProvidersConfig::default()
    }
}

fn snapshot_for_tests() -> SessionConfigSnapshot {
    let extended = crate::config::extended::ExtendedConfig {
        llm_mode: crate::config::extended::LlmMode::Defensive,
        ..crate::config::extended::ExtendedConfig::default()
    };
    SessionConfigSnapshot::new(0, provider_snapshot_config(), extended)
}

/// Criterion 2: engine components read config through the session handle,
/// and the value read matches the worker's current snapshot and generation.
#[test]
fn engine_reads_config_through_session_handle() {
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.llm_mode = crate::config::extended::LlmMode::Frontier;
    extended.max_primary_rounds = 9;
    let shared = Arc::new(RwLock::new(SessionConfigSnapshot::new(
        0,
        provider_snapshot_config(),
        extended,
    )));
    let handle = SessionConfigHandle::new(shared.clone());
    // The value the engine reads through the handle == the worker snapshot.
    assert_eq!(handle.generation(), 0);
    assert_eq!(
        handle.extended().llm_mode,
        crate::config::extended::LlmMode::Frontier
    );
    assert_eq!(handle.extended().max_primary_rounds, 9);
    assert_eq!(
        handle.providers().active_model.as_ref().unwrap().model,
        shared
            .read()
            .unwrap()
            .providers
            .active_model
            .as_ref()
            .unwrap()
            .model
    );
    // A re-resolution bumps the generation the live handle observes.
    let generation = replace_config_snapshot(
        &shared,
        SessionConfigSnapshot::new(
            0,
            crate::config::providers::ProvidersConfig::default(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    );
    assert_eq!(generation, 1);
    assert_eq!(handle.generation(), 1);
}

/// Criterion 3: a turn that started under generation N reads a consistent
/// view for its whole duration; a mid-turn re-resolution does not change
/// what the in-flight turn's (pinned) handle reads, and the next turn's
/// re-pin observes the new generation.
#[test]
fn turn_pinned_handle_view_survives_reresolve() {
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.llm_mode = crate::config::extended::LlmMode::Defensive;
    let shared = Arc::new(RwLock::new(SessionConfigSnapshot::new(
        0,
        crate::config::providers::ProvidersConfig::default(),
        extended,
    )));
    // Turn start: pin the current generation.
    let turn_handle = SessionConfigHandle::new(shared.clone()).repin();
    assert_eq!(turn_handle.generation(), 0);
    assert_eq!(
        turn_handle.extended().llm_mode,
        crate::config::extended::LlmMode::Defensive
    );

    // Mid-turn re-resolution over a new config (Frontier, generation 1).
    let updated = crate::config::extended::ExtendedConfig {
        llm_mode: crate::config::extended::LlmMode::Frontier,
        ..Default::default()
    };
    replace_config_snapshot(
        &shared,
        SessionConfigSnapshot::new(
            0,
            crate::config::providers::ProvidersConfig::default(),
            updated,
        ),
    );

    // The in-flight turn's pinned handle is unchanged.
    assert_eq!(turn_handle.generation(), 0);
    assert_eq!(
        turn_handle.extended().llm_mode,
        crate::config::extended::LlmMode::Defensive
    );

    // The next turn re-pins and sees the new generation/value.
    let next_turn = turn_handle.repin();
    assert_eq!(next_turn.generation(), 1);
    assert_eq!(
        next_turn.extended().llm_mode,
        crate::config::extended::LlmMode::Frontier
    );
}

/// Criterion 9 (behavior parity): for a fixed on-disk config tree, the
/// production `ConfigSource` resolution — the exact path the daemon uses to
/// build the snapshot the handle now serves — yields the same turn-relevant
/// values the pre-adoption direct disk reads produced. The expected values
/// are pinned here (captured from the fixture) so a resolution regression
/// fails this test.
#[test]
fn turn_config_values_match_pre_adoption_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(cockpit.join("providers")).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{
                "llm_mode": "defensive",
                "maxPrimaryRounds": 7,
                "redact": { "denylist": ["fixture-parity-secret"] },
                "delegation": { "maxParallel": 3 },
                "active_model": { "provider": "openai", "model": "gpt-parity" }
            }"#,
    )
    .unwrap();
    std::fs::write(
        cockpit.join("providers/openai.json"),
        r#"{"url":"https://api.openai.example/v1","models":[{"id":"gpt-parity"}]}"#,
    )
    .unwrap();

    // Resolve through the production ConfigSource (secret_ref::load_effective
    // + extended::load_for_cwd), then serve it through the handle.
    let (providers, extended) = crate::daemon::config_source::ConfigSource::production()
        .load(tmp.path())
        .expect("production config resolution");
    let handle = SessionConfigHandle::detached(SessionConfigSnapshot::new(0, providers, extended));

    let extended = handle.extended();
    assert_eq!(
        extended.llm_mode,
        crate::config::extended::LlmMode::Defensive
    );
    assert_eq!(extended.max_primary_rounds, 7);
    assert!(
        extended
            .redact
            .denylist
            .iter()
            .any(|entry| entry == "fixture-parity-secret"),
        "redact denylist should carry the fixture literal, got {:?}",
        extended.redact.denylist
    );
    assert_eq!(extended.delegation.max_parallel, 3);
    let active = handle
        .providers()
        .active_model
        .expect("active model resolved");
    assert_eq!(active.provider, "openai");
    assert_eq!(active.model, "gpt-parity");
}

#[test]
fn config_snapshot_event_still_carries_no_secrets() {
    let mut snapshot = snapshot_for_tests();
    snapshot
        .extended
        .redact
        .denylist
        .push("literal-config-secret".to_string());
    let wire = snapshot.to_proto(Uuid::new_v4());
    let encoded = serde_json::to_string(&wire).unwrap();
    assert!(!encoded.contains("sk-session-secret"), "{encoded}");
    assert!(!encoded.contains("openai-oauth"), "{encoded}");
    assert!(!encoded.contains("literal-config-secret"), "{encoded}");
    assert_eq!(wire.extended.redact.denylist, vec!["[redacted]"]);
    let provider = wire.providers.providers.get("openai").unwrap();
    assert!(provider.credential_configured);
    assert_eq!(provider.headers[0].value, "[redacted]");
    assert!(provider.entry.headers.is_empty());
    assert!(provider.entry.credential_ref.is_none());
}

#[test]
fn config_snapshot_carries_resolved_provider_view() {
    let wire = snapshot_for_tests().to_proto(Uuid::new_v4());
    assert_eq!(
        wire.providers.active_model.as_ref().unwrap().model,
        "gpt-test"
    );
    let provider = wire.providers.providers.get("openai").unwrap();
    assert_eq!(provider.entry.url, "https://api.openai.example/v1");
    assert_eq!(provider.entry.models[0].context_length, Some(128_000));
}

#[test]
fn provider_view_covers_enumerated_tui_consumer_fields() {
    let wire = snapshot_for_tests().to_proto(Uuid::new_v4());
    let provider = wire.providers.providers.get("openai").unwrap();
    assert!(wire.providers.active_model.is_some());
    assert!(wire.providers.category_defaults.contains_key("smart_code"));
    assert_eq!(provider.entry.name.as_deref(), Some("OpenAI"));
    assert_eq!(
        provider.entry.mode,
        Some(crate::config::extended::LlmMode::Normal)
    );
    assert_eq!(provider.entry.models[0].name.as_deref(), Some("GPT Test"));
    assert!(provider.credential_configured);
    assert_eq!(provider.headers[0].name, "Authorization");
}

#[test]
fn provider_view_requires_no_client_side_secret_resolution() {
    let wire = snapshot_for_tests().to_proto(Uuid::new_v4());
    let provider = wire.providers.providers.get("openai").unwrap();
    assert!(provider.entry.credential_ref.is_none());
    assert!(provider.entry.headers.is_empty());
    assert!(provider.credential_configured);
}

#[test]
fn config_snapshot_generation_increments_on_reresolve() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let generation = replace_config_snapshot(
        &snapshot,
        SessionConfigSnapshot::new(
            0,
            crate::config::providers::ProvidersConfig::default(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    );
    assert_eq!(generation, 1);
}

#[test]
fn config_snapshot_generation_stable_without_reresolve() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let before = snapshot.read().unwrap().generation;
    let _current = snapshot.read().unwrap().clone();
    assert_eq!(snapshot.read().unwrap().generation, before);
}

#[test]
fn invalid_config_reresolve_keeps_last_good_snapshot() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let failed: anyhow::Result<(
        crate::config::providers::ProvidersConfig,
        crate::config::extended::ExtendedConfig,
    )> = Err(anyhow::anyhow!("bad config"));
    if let Ok((providers, extended)) = failed {
        replace_config_snapshot(
            &snapshot,
            SessionConfigSnapshot::new(0, providers, extended),
        );
    }
    let current = snapshot.read().unwrap();
    assert_eq!(current.generation, 0);
    assert!(current.providers.providers.contains_key("openai"));
}

#[test]
fn config_reresolve_does_not_mutate_inflight_turn_view() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let inflight = snapshot.read().unwrap().clone();
    let updated = crate::config::extended::ExtendedConfig {
        llm_mode: crate::config::extended::LlmMode::Frontier,
        ..crate::config::extended::ExtendedConfig::default()
    };
    replace_config_snapshot(
        &snapshot,
        SessionConfigSnapshot::new(
            0,
            crate::config::providers::ProvidersConfig::default(),
            updated,
        ),
    );
    assert_eq!(
        inflight.extended.llm_mode,
        crate::config::extended::LlmMode::Defensive
    );
    assert_eq!(
        snapshot.read().unwrap().extended.llm_mode,
        crate::config::extended::LlmMode::Frontier
    );
}

#[test]
fn llm_mode_reads_are_consistent_within_a_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let snapshot = snapshot_for_tests();
    let session = Session::create(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
    )
    .unwrap();
    session.set_active_model("openai", "gpt-test").unwrap();
    let first =
        resolve_effective_llm_mode(&session, &snapshot.providers, snapshot.extended.llm_mode);
    let second =
        resolve_effective_llm_mode(&session, &snapshot.providers, snapshot.extended.llm_mode);
    assert_eq!(first, crate::config::extended::LlmMode::Normal);
    assert_eq!(first, second);
}

#[test]
fn worker_uses_registry_resolved_config_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let snapshot = snapshot_for_tests();
    let session = Session::create(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
    )
    .unwrap();
    session.set_active_model("openai", "gpt-test").unwrap();
    crate::config::extended::reset_load_for_cwd_call_count();
    let _ = resolve_effective_llm_mode(&session, &snapshot.providers, snapshot.extended.llm_mode);
    assert_eq!(crate::config::extended::load_for_cwd_call_count(), 0);
}

#[test]
fn worker_broadcast_delivers_config_snapshot_to_subscriber() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap());
    let locks = Arc::new(LockManager::from_db(db).unwrap());
    let (handle, _rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
    replace_config_snapshot(
        &handle.config_snapshot,
        SessionConfigSnapshot::new(
            0,
            provider_snapshot_config(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    );
    let mut events = handle.subscribe();
    handle.broadcast_config_snapshot();
    assert!(matches!(
        events.try_recv().unwrap().event,
        proto::Event::ConfigSnapshot { snapshot }
            if snapshot.session_id == handle.session_id && snapshot.generation == 1
    ));
}

#[test]
fn dispatch_reresolve_fans_out_to_all_attached_clients() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap());
    let locks = Arc::new(LockManager::from_db(db).unwrap());
    let (handle, _rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
    let mut a = handle.subscribe();
    let mut b = handle.subscribe();
    replace_config_snapshot(
        &handle.config_snapshot,
        SessionConfigSnapshot::new(
            0,
            provider_snapshot_config(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    );
    handle.broadcast_config_snapshot();
    assert!(matches!(
        a.try_recv().unwrap().event,
        proto::Event::ConfigSnapshot { snapshot } if snapshot.generation == 1
    ));
    assert!(matches!(
        b.try_recv().unwrap().event,
        proto::Event::ConfigSnapshot { snapshot } if snapshot.generation == 1
    ));
}

/// Guard (`engine-config-snapshot-adoption`, criterion 1): no session- or
/// turn-scoped code re-reads config from disk. Every direct call to
/// `extended::load_for_cwd`, `secret_ref::load_effective`, or
/// `ConfigDoc::load_effective` must live in `#[cfg(test)]` code, in the
/// trust-aware `ConfigSource`, or in one of the explicitly enumerated
/// session-less files below (each of which runs outside any session — a
/// one-shot subcommand, a daemon RPC handler, the scheduler callback, the
/// session-creation snapshot, or the definition site — and resolves config
/// once at its own boundary). Any other occurrence is a turn-scoped read
/// that bypasses the session snapshot and fails this guard.
#[test]
fn session_scoped_code_has_no_direct_config_reads() {
    fn collect_rs(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    // Session-less surfaces that legitimately keep direct config reads.
    // Enumerated, never silently exempted (criterion 4). `config_source.rs`
    // is the trust-aware resolution seam itself; `approval/store.rs` is
    // carved out for sibling `approval-policy-live-reload`.
    const SESSION_LESS_FILES: &[&str] = &[
        "daemon/config_source.rs",
        "secret_ref.rs",
        "wizard/apply.rs",
        "init.rs",
        "welcome.rs",
        "diagnostics.rs",
        "packages/clone.rs",
        "agents/mod.rs",
        "session/export/mod.rs",
        "skills/curator.rs",
        "auto_title.rs",
        "engine/builtin/mod.rs",
        "approval/store.rs",
        // Session bootstrap: captures a config-derived snapshot on the row
        // before any worker/handle exists.
        "session/lifecycle.rs",
    ];

    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src_dir, &mut files);

    // The primitive disk loaders plus the `auto_title::load_configs_for`
    // convenience that pairs them: a turn-scoped call to any of these
    // bypasses the session snapshot.
    let banned = [
        "load_for_cwd(",
        "secret_ref::load_effective(",
        "ConfigDoc::load_effective(",
        "load_configs_for(",
    ];

    let offenders: Vec<String> = files
        .into_iter()
        .filter(|path| {
            let rel = path.strip_prefix(&src_dir).unwrap();
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            // Skip test files/dirs and the enumerated session-less files.
            let is_test_file = rel
                .components()
                .any(|c| c.as_os_str() == "tests" || c.as_os_str() == "tests.rs");
            !is_test_file && !SESSION_LESS_FILES.contains(&rel_str.as_str())
        })
        .flat_map(|path| {
            let text = std::fs::read_to_string(&path).unwrap();
            // Track `#[cfg(test)]`-guarded items by brace depth so test-only
            // code (e.g. `SessionConfigHandle::from_disk_for_tests`) is not
            // flagged.
            let mut depth: i32 = 0;
            let mut cfg_test_pending = false;
            let mut cfg_test_depth: Option<i32> = None;
            let mut hits = Vec::new();
            for (idx, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                let in_cfg_test = cfg_test_depth.is_some();
                if !in_cfg_test
                    && !trimmed.starts_with("//")
                    && banned.iter().any(|needle| line.contains(needle))
                {
                    hits.push(format!("{}:{}:{}", path.display(), idx + 1, line.trim()));
                }
                if trimmed.contains("#[cfg(test)]") {
                    cfg_test_pending = true;
                }
                let opens = line.matches('{').count() as i32;
                let closes = line.matches('}').count() as i32;
                if cfg_test_pending && opens > 0 {
                    cfg_test_depth = Some(depth);
                    cfg_test_pending = false;
                }
                depth += opens - closes;
                if let Some(start) = cfg_test_depth
                    && depth <= start
                {
                    cfg_test_depth = None;
                }
            }
            hits
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "turn-scoped code must read config through the session snapshot handle, \
             not directly from disk:\n{offenders:#?}"
    );
}

#[test]
fn config_reresolve_rereads_trust_policy() {
    let dispatch = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/daemon/server/dispatch.rs"),
    )
    .unwrap();
    let refresh = dispatch
        .split("Request::RefreshConfig =>")
        .nth(1)
        .and_then(|tail| tail.split("Request::RecordUsage").next())
        .expect("RefreshConfig dispatch arm");
    let trust_pos = refresh
        .find("resolve_workspace_trust_policy_from_db")
        .expect("refresh re-reads trust policy");
    let load_pos = refresh
        .find("load_with_trust")
        .expect("refresh loads through ConfigSource with trust");
    assert!(
        trust_pos < load_pos,
        "trust must be re-read before config load"
    );
}

#[test]
fn queue_item_carries_display_text() {
    let item = crate::engine::message::QueuedUserMessage {
        id: uuid::Uuid::new_v4(),
        status: crate::engine::message::QueueItemStatus::Queued,
        text: "<file path=\"src/lib.rs\">expanded</file>".to_string(),
        display_text: Some("review @src/lib.rs".to_string()),
        target: crate::engine::message::QueueTarget::root("Build"),
    };

    let proto = queue_item_to_proto(item);
    assert!(proto.text.starts_with("<file"));
    assert_eq!(proto.display_text.as_deref(), Some("review @src/lib.rs"));
}
