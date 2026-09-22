//! Process crash coverage through ordinary dispatch, boot classification, and
//! the real session worker. Only the tool's external service and crash pauses
//! are fixtures; intent creation, replay, decisions, and status are production.
use super::*;
#[cfg(unix)]
use crate::engine::tool::ToolBox;
use crate::engine::{
    agent::Agent,
    tool::{Tool, ToolCtx, ToolEffect, ToolIdempotency, ToolOutput},
};
#[cfg(unix)]
use rig::message::{AssistantContent, Message, UserContent};
use std::sync::OnceLock;

#[derive(Clone)]
struct Fixture {
    class: ToolIdempotency,
    root: PathBuf,
    pause: Option<String>,
}

fn fixtures() -> &'static StdMutex<HashMap<Uuid, Fixture>> {
    static FIXTURES: OnceLock<StdMutex<HashMap<Uuid, Fixture>>> = OnceLock::new();
    FIXTURES.get_or_init(Default::default)
}

pub(crate) async fn checkpoint(session_id: Uuid, boundary: &str) {
    let fixture = fixtures().lock().unwrap().get(&session_id).cloned();
    if let Some(fixture) = fixture
        && fixture.pause.as_deref() == Some(boundary)
    {
        std::fs::write(fixture.root.join("ready"), boundary).unwrap();
        std::future::pending::<()>().await;
    }
}

pub(crate) fn install_tool(session_id: Uuid, mut agent: Agent) -> Agent {
    if let Some(fixture) = fixtures().lock().unwrap().get(&session_id).cloned() {
        agent.tools = agent.tools.with(Arc::new(EffectTool(fixture)));
    }
    agent
}

struct EffectTool(Fixture);

#[async_trait::async_trait]
impl Tool for EffectTool {
    fn name(&self) -> &str {
        "crash_matrix_effect"
    }
    fn description(&self) -> &str {
        "Persistent crash-matrix service fixture"
    }
    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({"type":"object"})
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }
    fn idempotency(&self) -> ToolIdempotency {
        self.0.class
    }
    fn authorizes_own_effects(&self) -> bool {
        true
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolCtx) -> anyhow::Result<ToolOutput> {
        let call_id = ctx.current_tool_call_id.as_ref().unwrap().to_string();
        let intent = ctx
            .session
            .db
            .tool_execution_intent_for_call(ctx.session.id, call_id)
            .await?
            .expect("write-ahead intent must exist inside the actual tool");
        let key = args
            .get("_cockpit_idempotency_key")
            .and_then(|v| v.as_str());
        assert_eq!(key, intent.idempotency_key.as_deref());
        let mut attempts = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.0.root.join("attempts"))?;
        writeln!(attempts, "{}", key.unwrap_or("unkeyed"))?;
        attempts.sync_all()?;
        let effect = self.0.root.join("effect");
        match self.0.class {
            ToolIdempotency::Idempotent => std::fs::write(effect, "done\n")?,
            ToolIdempotency::IdempotentWithKey => {
                // A fake external service's durable key receipt. The caller
                // must reuse the original key to obtain the same effect.
                let receipt = self.0.root.join(format!("receipt-{}", key.unwrap()));
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(receipt)
                {
                    Ok(receipt) => {
                        receipt.sync_all()?;
                        let mut file = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(effect)?;
                        writeln!(file, "done")?;
                        file.sync_all()?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            ToolIdempotency::NotIdempotent => {
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(effect)?;
                writeln!(file, "done")?;
                file.sync_all()?;
            }
        }
        Ok(ToolOutput::text("done"))
    }
}

#[cfg(unix)]
fn class(value: &str) -> ToolIdempotency {
    match value {
        "safe" => ToolIdempotency::Idempotent,
        "keyed" => ToolIdempotency::IdempotentWithKey,
        "ambiguous" => ToolIdempotency::NotIdempotent,
        _ => panic!("unknown fixture class"),
    }
}

#[cfg(unix)]
fn line_count(path: &Path) -> usize {
    match std::fs::read_to_string(path) {
        Ok(text) => text.lines().count(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => panic!("reading fixture effect: {error}"),
    }
}

async fn worker_barrier(handle: &SessionWorkerHandle) {
    // This acknowledged inbox operation can only run after startup's sweep
    // and automatic replay. It does not enqueue inference or touch a tool.
    let (respond_to, reply) = tokio::sync::oneshot::channel();
    handle
        .send_work(SessionWork::RemoveQueuedUserMessage {
            queue_item_id: Uuid::new_v4(),
            #[cfg(feature = "remote")]
            remote_operation: None,
            respond_to,
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), reply)
        .await
        .expect("worker reaches inbox after startup")
        .unwrap()
        .unwrap();
}

async fn assert_status(ctx: &Arc<DaemonContext>, expected: Vec<Uuid>) {
    let Response::DaemonStatus {
        pending_recovery_sessions,
        ..
    } = dispatch_matrix_request(ctx, Request::DaemonStatus)
        .await
        .unwrap()
    else {
        panic!("expected daemon status")
    };
    assert_eq!(pending_recovery_sessions, expected);
}

async fn answer(handle: &SessionWorkerHandle, interrupt_id: Uuid, selected_id: &str) {
    handle
        .send_work(SessionWork::ResolveInterrupt {
            interrupt_id,
            response: proto::ResolveResponse::Single {
                selected_id: selected_id.into(),
            },
            governed_network_attachment: None,
        })
        .await
        .unwrap();
    worker_barrier(handle).await;
}

async fn stop_worker(handle: &SessionWorkerHandle, join: tokio::task::JoinHandle<()>) {
    handle
        .send_work(SessionWork::Shutdown {
            pause_for_resume: false,
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), join)
        .await
        .expect("worker shuts down")
        .unwrap();
}

#[tokio::test]
async fn daemon_status_after_recovery_lists_the_pending_session() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            ctx.db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    let intent = ctx
        .db
        .begin_tool_execution_intent(crate::db::tool_recovery::BeginToolExecutionIntent {
            session_id: session.id,
            call_id: "crash-call".into(),
            tool: "bash".into(),
            args: serde_json::json!({"command":"printf done"}),
            generation: 0,
            idempotency: crate::db::tool_recovery::ToolIdempotency::NotIdempotent,
            idempotency_key: None,
        })
        .await
        .unwrap();
    reconcile_crash_interrupted_tools(&ctx.db).await.unwrap();
    let (handle, join) = crate::daemon::session_worker::tests::spawn_recovery_test_worker(
        session.clone(),
        tmp.path(),
        false,
    );
    worker_barrier(&handle).await;
    assert_eq!(
        ctx.db
            .get_interrupt(intent.intent_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        crate::db::needs_attention::InterruptState::Open
    );
    assert_eq!(
        ctx.db.list_open_interrupts(session.id).await.unwrap().len(),
        1
    );
    assert_status(&ctx, vec![session.id]).await;
    answer(&handle, intent.intent_id, "inspect").await;
    assert_status(&ctx, vec![session.id]).await;
    answer(&handle, intent.intent_id, "skip").await;
    assert_status(&ctx, vec![]).await;
    assert_eq!(
        ctx.db
            .get_interrupt(intent.intent_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        crate::db::needs_attention::InterruptState::Resolved
    );
    stop_worker(&handle, join).await;
}

#[cfg(unix)]
#[tokio::test]
async fn production_crash_matrix_child() {
    let Ok(root) = std::env::var("COCKPIT_RECOVERY_MATRIX_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let phase = std::env::var("COCKPIT_RECOVERY_MATRIX_PHASE").unwrap();
    let boundary = std::env::var("COCKPIT_RECOVERY_MATRIX_BOUNDARY").unwrap();
    let class = class(&std::env::var("COCKPIT_RECOVERY_MATRIX_CLASS").unwrap());
    let responses = std::env::var("COCKPIT_RECOVERY_MATRIX_RESPONSES").unwrap() == "true";
    let choice = std::env::var("COCKPIT_RECOVERY_MATRIX_CHOICE").unwrap();
    let generation = crate::daemon::supervisor::worker_generation();
    let db = Db::open_supervised_worker_for_test(&root.join("db.sqlite"), generation).unwrap();
    let fixture = Fixture {
        class,
        root: root.clone(),
        pause: (phase == "crash").then(|| boundary.clone()),
    };
    if phase == "crash" {
        let session = Arc::new(
            Session::create_for_test(
                db,
                root.clone(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        std::fs::write(root.join("session_id"), session.id.to_string()).unwrap();
        fixtures()
            .lock()
            .unwrap()
            .insert(session.id, fixture.clone());
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text":"run fixture"}),
            )
            .await
            .unwrap();
        // Durable assistant identity, as reconstructed from an interrupted
        // transcript. This is deliberately present before intent creation.
        session
            .record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some("Build"),
                Some("call-1"),
                &serde_json::json!({"tool":"crash_matrix_effect", "wire_input":{},
                "provider_call_id":"provider-call-1", "provider_item_id":"item-1"}),
            )
            .await
            .unwrap();
        let call = rig::message::ToolCall {
            id: rig::message::ToolCallId::new_or_mint("call-1"),
            provider: rig::message::ProviderCallId::new("provider-call-1")
                .map(|p| p.with_item_id("item-1")),
            function: rig::message::ToolFunction {
                name: "crash_matrix_effect".into(),
                arguments: serde_json::json!({}),
            },
            signature: None,
            additional_params: None,
        };
        crate::engine::agent::tool_dispatch::tests::dispatch_crash_matrix_call(
            session,
            &root,
            ToolBox::new().with(Arc::new(EffectTool(fixture))),
            call,
        )
        .await;
        return;
    }
    let session_id =
        Uuid::parse_str(&std::fs::read_to_string(root.join("session_id")).unwrap()).unwrap();
    let session = Arc::new(
        Session::resume_for_test(
            db.clone(),
            session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap(),
    );
    fixtures().lock().unwrap().insert(session_id, fixture);
    let mut context = DaemonContext::new(
        db.clone(),
        Arc::new(LockManager::in_memory(db.clone())),
        unique_test_paths(true),
        crate::daemon::terminal::test_host_factory(),
        stub_config_source(),
    );
    install_test_redaction_key_resolver(&mut context);
    let ctx = Arc::new(context);
    // Invoke the exact common boot classifier, twice to prove deduplication.
    reconcile_crash_interrupted_tools(&db).await.unwrap();
    reconcile_crash_interrupted_tools(&db).await.unwrap();
    let policy = if responses {
        crate::engine::rehydrate::RehydratePolicy::strict()
    } else {
        crate::engine::rehydrate::RehydratePolicy::heal()
    };
    if boundary != "before_intent" {
        let history = crate::engine::rehydrate::rehydrate_session_with_policy(
            &db, session_id, "Build", policy,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(history.heals.is_empty());
        assert_eq!(
            result_count(&history.history),
            0,
            "open intent must not get a fabricated result"
        );
        assert_eq!(call_count(&history.history), 1);
    }
    let (handle, join) = crate::daemon::session_worker::tests::spawn_recovery_test_worker(
        session.clone(),
        &root,
        responses,
    );
    worker_barrier(&handle).await;
    assert_eq!(
        handle.repair_required().is_some(),
        responses && boundary == "before_intent",
        "only an orphan without a durable intent requires Responses repair"
    );
    let ambiguous = class == ToolIdempotency::NotIdempotent && boundary != "before_intent";
    if ambiguous {
        let open = db.list_open_interrupts(session_id).await.unwrap();
        assert_eq!(
            open.len(),
            1,
            "exactly one live answerable decision after worker startup"
        );
        assert_eq!(
            open[0].state,
            crate::db::needs_attention::InterruptState::Open
        );
        let interrupt_id = open[0].interrupt_id;
        assert_eq!(
            line_count(&root.join("attempts")),
            usize::from(boundary == "after_result")
        );
        assert_status(&ctx, vec![session_id]).await;
        answer(&handle, interrupt_id, "inspect").await;
        assert_eq!(db.list_open_interrupts(session_id).await.unwrap().len(), 1);
        assert_status(&ctx, vec![session_id]).await;
        answer(&handle, interrupt_id, &choice).await;
        let receipt = db
            .get_interrupt(interrupt_id)
            .await
            .unwrap()
            .expect("durable answer survives intent deletion");
        assert_eq!(
            receipt.state,
            crate::db::needs_attention::InterruptState::Resolved
        );
        assert_eq!(
            receipt.response,
            Some(proto::ResolveResponse::Single {
                selected_id: choice.clone()
            })
        );
        assert_eq!(
            line_count(&root.join("effect")),
            usize::from(boundary == "after_result") + usize::from(choice == "rerun")
        );
        // A duplicate answer cannot re-execute the tool.
        answer(&handle, interrupt_id, &choice).await;
        assert_eq!(
            line_count(&root.join("attempts")),
            usize::from(boundary == "after_result") + usize::from(choice == "rerun")
        );
    } else {
        assert!(
            db.list_open_interrupts(session_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            line_count(&root.join("effect")),
            usize::from(boundary != "before_intent")
        );
        assert_eq!(
            line_count(&root.join("attempts")),
            match boundary.as_str() {
                "before_intent" => 0,
                "after_intent" => 1,
                "after_result" => 2,
                _ => unreachable!(),
            }
        );
        if class == ToolIdempotency::IdempotentWithKey && boundary == "after_result" {
            let keys = std::fs::read_to_string(root.join("attempts")).unwrap();
            let keys = keys.lines().collect::<Vec<_>>();
            assert_eq!(keys.len(), 2);
            assert_eq!(
                keys[0], keys[1],
                "successor reuses the durable external idempotency key"
            );
            assert_ne!(keys[0], "unkeyed");
        }
    }
    assert!(
        db.list_open_tool_execution_intents()
            .await
            .unwrap()
            .is_empty()
    );
    assert_status(&ctx, vec![]).await;
    let expected_result = boundary != "before_intent" && (!ambiguous || choice == "rerun");
    assert_eq!(
        db.list_tool_calls_for_session(session_id)
            .await
            .unwrap()
            .len(),
        usize::from(expected_result)
    );
    if expected_result {
        let rebuilt = crate::engine::rehydrate::rehydrate_session_with_policy(
            &db, session_id, "Build", policy,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            result_count(&rebuilt.history),
            1,
            "one model-visible result per recovered call"
        );
        assert_eq!(call_count(&rebuilt.history), 1);
        assert!(rebuilt.heals.is_empty());
    }
    stop_worker(&handle, join).await;
    // A second successor must not reopen the decision or execute again.
    let attempts = line_count(&root.join("attempts"));
    reconcile_crash_interrupted_tools(&db).await.unwrap();
    assert_status(&ctx, vec![]).await;
    assert_eq!(line_count(&root.join("attempts")), attempts);
    fixtures().lock().unwrap().remove(&session_id);
}

#[cfg(unix)]
fn result_count(history: &[Message]) -> usize {
    history
        .iter()
        .map(|message| match message {
            Message::User { content } => content
                .iter()
                .filter(|part| matches!(part, UserContent::ToolResult(_)))
                .count(),
            _ => 0,
        })
        .sum()
}

#[cfg(unix)]
fn call_count(history: &[Message]) -> usize {
    history
        .iter()
        .map(|message| match message {
            Message::Assistant { content, .. } => content
                .iter()
                .filter(|part| matches!(part, AssistantContent::ToolCall(_)))
                .count(),
            _ => 0,
        })
        .sum()
}

#[cfg(unix)]
#[test]
fn production_crash_matrix_kills_dispatch_and_recovers_through_session_worker() {
    use std::process::{Command, Stdio};
    let executable = std::env::current_exe().unwrap();
    let mut cells = 0;
    for responses in [false, true] {
        for class in ["safe", "keyed", "ambiguous"] {
            for boundary in ["before_intent", "after_intent", "after_result"] {
                let choices: &[&str] = if class == "ambiguous" && boundary != "before_intent" {
                    &["skip", "rerun"]
                } else {
                    &["skip"]
                };
                for choice in choices {
                    let tmp = tempfile::tempdir().unwrap();
                    let log_path = tmp.path().join("child.log");
                    let command = |phase: &str, generation: &str| {
                        let mut command = Command::new(&executable);
                        command.args(["--exact", "daemon::server::tests::tool_recovery_tests::production_crash_matrix_child", "--nocapture"])
                            .env("COCKPIT_RECOVERY_MATRIX_ROOT", tmp.path())
                            .env("COCKPIT_RECOVERY_MATRIX_PHASE", phase)
                            .env("COCKPIT_RECOVERY_MATRIX_BOUNDARY", boundary)
                            .env("COCKPIT_RECOVERY_MATRIX_CLASS", class)
                            .env("COCKPIT_RECOVERY_MATRIX_RESPONSES", responses.to_string())
                            .env("COCKPIT_RECOVERY_MATRIX_CHOICE", choice)
                            .env("COCKPIT_WORKER_GENERATION", generation)
                            .stdin(Stdio::null())
                            .stdout(std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap())
                            .stderr(std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap());
                        command
                    };
                    let mut child = command("crash", "1").spawn().unwrap();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                    while !tmp.path().join("ready").exists() {
                        assert!(
                            child.try_wait().unwrap().is_none(),
                            "predecessor exited early: {}",
                            std::fs::read_to_string(&log_path).unwrap()
                        );
                        if std::time::Instant::now() >= deadline {
                            child.kill().unwrap();
                            child.wait().unwrap();
                            panic!(
                                "predecessor missed checkpoint: {}",
                                std::fs::read_to_string(&log_path).unwrap()
                            );
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    assert_eq!(
                        std::fs::read_to_string(tmp.path().join("ready")).unwrap(),
                        boundary
                    );
                    child.kill().unwrap();
                    assert!(!child.wait().unwrap().success());
                    let mut successor = command("recover", "2").spawn().unwrap();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                    let status = loop {
                        if let Some(status) = successor.try_wait().unwrap() {
                            break status;
                        }
                        if std::time::Instant::now() >= deadline {
                            successor.kill().unwrap();
                            successor.wait().unwrap();
                            panic!(
                                "successor stalled: {}",
                                std::fs::read_to_string(&log_path).unwrap()
                            );
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    };
                    assert!(
                        status.success(),
                        "{class}/{boundary}/{choice}/responses={responses}: {}",
                        std::fs::read_to_string(&log_path).unwrap()
                    );
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, 22);
}
