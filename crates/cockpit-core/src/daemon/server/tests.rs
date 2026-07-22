use super::attachments::*;
use super::authz::*;
use super::dispatch::*;
use super::sessions::*;
use super::*;
use crate::daemon::session_worker::{SessionWork, SessionWorkerHandle};
use crate::daemon::shutdown::ShutdownPhase;
use crate::session::Session;
use std::collections::{BTreeSet, HashMap, HashSet};
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

fn remote_principal() -> ClientPrincipal {
    ClientPrincipal::Remote(principal::RemotePrincipal {
        user_id: "remote-user".to_string(),
        grants: vec![principal::PrincipalGrant {
            scope: principal::PrincipalScope::AgentReadonly,
            project_root: None,
        }],
    })
}

fn table_for(secret: &str) -> Arc<RedactionTable> {
    let cfg = crate::config::extended::RedactConfig {
        enabled: true,
        scan_environment: false,
        scan_dotenv: false,
        scan_ssh_keys: false,
        denylist: vec![secret.to_string()],
        placeholder: "[redacted]".to_string(),
        ..crate::config::extended::RedactConfig::default()
    };
    Arc::new(RedactionTable::build(&cfg, Path::new(".")).unwrap())
}

#[tokio::test]
async fn detached_client_cannot_remove_editable_queued_messages() {
    let ctx = test_ctx();
    let client = crate::daemon::client::DaemonClient::from_in_process(ctx);

    let err = client
        .request(Request::RemoveEditableQueuedUserMessages { target_id: None })
        .await
        .expect("detached client receives typed daemon response")
        .expect_err("attached-session request is rejected before attach");

    assert_eq!(err.code, ErrorCode::NotAttached);
}

#[tokio::test]
async fn read_session_messages_requires_read_access_returns_page_and_does_not_spawn_worker() {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    let seq = ctx
        .db
        .insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "hello"}),
        )
        .unwrap();
    let request = Request::ReadSessionMessages {
        session_id: session.session_id,
        before_seq: None,
        limit: 20,
    };
    let grant = crate::daemon::principal::PrincipalGrant {
        scope: crate::daemon::principal::PrincipalScope::AgentReadonly,
        project_root: Some("/repo".to_string()),
    };
    let mut denied = remote_state_with_grants(vec![grant.clone()]);
    let error = handle_request(request.clone(), &mut denied, &ctx)
        .await
        .expect_err("unshared session is not readable to a remote principal");
    assert_eq!(error.code, ErrorCode::Authorization);

    ctx.db
        .set_session_shared_with_collaborators(session.session_id, true)
        .unwrap();
    let mut allowed = remote_state_with_grants(vec![grant]);
    let response = handle_request(request, &mut allowed, &ctx)
        .await
        .expect("readonly collaborator can read shared session messages");
    let Response::SessionMessages {
        session_id,
        messages,
        has_more,
    } = response
    else {
        panic!("expected SessionMessages response");
    };
    assert_eq!(session_id, session.session_id);
    assert!(!has_more);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].seq, seq);
    assert_eq!(messages[0].role, proto::MessageRole::User);
    assert_eq!(messages[0].text, "hello");
    assert!(
        !ctx.registry
            .active_session_ids()
            .contains(&session.session_id),
        "read-messages is a DB/RPC read and must not create a session worker"
    );
}

#[tokio::test]
async fn read_history_page_requires_read_access_returns_page_and_does_not_spawn_worker() {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    let seq = ctx
        .db
        .insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "hello"}),
        )
        .unwrap();
    let request = Request::ReadHistoryPage {
        session_id: session.session_id,
        before_seq: None,
        limit: 20,
    };
    let grant = crate::daemon::principal::PrincipalGrant {
        scope: crate::daemon::principal::PrincipalScope::AgentReadonly,
        project_root: Some("/repo".to_string()),
    };
    let mut denied = remote_state_with_grants(vec![grant.clone()]);
    let error = handle_request(request.clone(), &mut denied, &ctx)
        .await
        .expect_err("unshared session is not readable to a remote principal");
    assert_eq!(error.code, ErrorCode::Authorization);

    ctx.db
        .set_session_shared_with_collaborators(session.session_id, true)
        .unwrap();
    let mut allowed = remote_state_with_grants(vec![grant]);
    let response = handle_request(request, &mut allowed, &ctx)
        .await
        .expect("readonly collaborator can read shared history pages");
    let Response::HistoryPage {
        session_id,
        entries,
        has_more,
        oldest_seq,
    } = response
    else {
        panic!("expected HistoryPage response");
    };
    assert_eq!(session_id, session.session_id);
    assert!(!has_more);
    assert_eq!(oldest_seq, Some(seq));
    assert_eq!(entries.len(), 1);
    assert!(matches!(
        &entries[0],
        proto::HistoryEntry::User { text, seq: got, .. } if text == "hello" && *got == seq
    ));
    assert!(
        !ctx.registry
            .active_session_ids()
            .contains(&session.session_id),
        "read-history-page is a DB/RPC read and must not create a session worker"
    );
}

#[tokio::test]
async fn read_history_page_denied_without_session_read_access() {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    let request = Request::ReadHistoryPage {
        session_id: session.session_id,
        before_seq: None,
        limit: 20,
    };
    let grant = crate::daemon::principal::PrincipalGrant {
        scope: crate::daemon::principal::PrincipalScope::AgentReadonly,
        project_root: Some("/repo".to_string()),
    };
    let mut state = remote_state_with_grants(vec![grant]);

    let error = handle_request(request, &mut state, &ctx)
        .await
        .expect_err("unshared session is denied to remote readonly principal");

    assert_eq!(error.code, ErrorCode::Authorization);
    assert_eq!(error.message, "remote principal cannot access this session");
}

#[tokio::test]
async fn goal_rpc_reads_sets_and_clears() {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    ctx.db
        .create_session_goal(
            session.session_id,
            &session.project_id,
            "ship daemon goal rpc",
            Some("context secret"),
            Some(100),
        )
        .unwrap();
    let mut state = owner_state();

    let response = handle_request(
        Request::GoalStatus {
            session_id: session.session_id,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("goal status");
    let Response::GoalStatus { goal: Some(goal) } = response else {
        panic!("expected goal status response");
    };
    assert_eq!(goal.session_id, session.session_id);
    assert_eq!(goal.objective, "ship daemon goal rpc");
    assert_eq!(goal.status, proto::GoalStatus::Active);

    let response = handle_request(
        Request::SetGoalStatus {
            session_id: session.session_id,
            status: proto::GoalStatus::Paused,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("pause goal");
    let Response::GoalUpdated { goal } = response else {
        panic!("expected goal updated response");
    };
    assert_eq!(goal.status, proto::GoalStatus::Paused);

    let response = handle_request(
        Request::SetGoalStatus {
            session_id: session.session_id,
            status: proto::GoalStatus::Active,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("resume goal");
    let Response::GoalUpdated { goal } = response else {
        panic!("expected goal updated response");
    };
    assert_eq!(goal.status, proto::GoalStatus::Active);

    let response = handle_request(
        Request::ClearGoal {
            session_id: session.session_id,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("clear goal");
    assert!(matches!(response, Response::GoalCleared { cleared: true }));

    let response = handle_request(
        Request::GoalStatus {
            session_id: session.session_id,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("goal status after clear");
    assert!(matches!(response, Response::GoalStatus { goal: None }));
}

#[tokio::test]
async fn goal_change_is_visible_to_live_worker() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, session_id, _work_rx) = attached_state_with_worker_receiver(&ctx, tmp.path());
    let session = ctx.db.get_session(session_id).unwrap().unwrap();
    ctx.db
        .create_session_goal(
            session_id,
            &session.project_id,
            "ship live goal coherence",
            None,
            Some(100),
        )
        .unwrap();
    let live_before = state
        .attached
        .as_ref()
        .expect("attached live worker")
        .handle
        .session();

    let response = handle_request(
        Request::SetGoalStatus {
            session_id,
            status: proto::GoalStatus::Paused,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("pause live goal");
    assert!(matches!(
        response,
        Response::GoalUpdated {
            goal: proto::GoalSummary {
                status: proto::GoalStatus::Paused,
                ..
            }
        }
    ));

    let live_after = state
        .attached
        .as_ref()
        .expect("attached live worker")
        .handle
        .session();
    assert!(
        Arc::ptr_eq(&live_before, &live_after),
        "goal change must not require replacing the live session"
    );
    let goal = live_after
        .db
        .current_session_goal(live_after.id, false)
        .unwrap()
        .expect("goal visible through live worker session handle");
    assert_eq!(goal.status, proto::GoalStatus::Paused);
}

#[tokio::test]
async fn goal_change_midturn_persists_immediately_and_applies_next_turn() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (state, session_id, mut work_rx) = attached_state_with_worker_receiver(&ctx, tmp.path());
    let session = ctx.db.get_session(session_id).unwrap().unwrap();
    ctx.db
        .create_session_goal(
            session_id,
            &session.project_id,
            "ship midturn goal boundary",
            None,
            Some(100),
        )
        .unwrap();

    let first_ctx = ctx.clone();
    let first = tokio::spawn(async move {
        let mut state = state;
        let result = handle_request(
            Request::SendUserMessage {
                text: "first turn".into(),
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs: Vec::new(),
                forced_skill: None,
            },
            &mut state,
            &first_ctx,
        )
        .await;
        (state, result)
    });
    let first_work = tokio::time::timeout(std::time::Duration::from_secs(2), work_rx.recv())
        .await
        .expect("first turn delivered")
        .expect("first turn work");
    let SessionWork::UserMessage {
        submission,
        respond_to,
    } = first_work
    else {
        panic!("expected first user message work");
    };
    assert_eq!(submission.text, "first turn");
    assert_eq!(
        ctx.db
            .current_session_goal(session_id, false)
            .unwrap()
            .expect("goal exists")
            .status,
        crate::db::session_goals::GoalStatus::Active
    );

    let mut rpc_state = owner_state();
    handle_request(
        Request::SetGoalStatus {
            session_id,
            status: proto::GoalStatus::Paused,
        },
        &mut rpc_state,
        &ctx,
    )
    .await
    .expect("midturn pause persists");
    assert_eq!(
        ctx.db
            .current_session_goal(session_id, false)
            .unwrap()
            .expect("goal persists immediately")
            .status,
        crate::db::session_goals::GoalStatus::Paused
    );

    let item = proto::QueueItem {
        id: Uuid::new_v4(),
        status: proto::QueueItemStatus::Queued,
        text: submission.text.clone(),
        display_text: None,
        target: proto::QueueTarget::default(),
    };
    respond_to.send((item.clone(), vec![item])).unwrap();
    let (state, first_response) = first.await.expect("first turn request joins");
    assert!(matches!(
        first_response.expect("first turn completes"),
        Response::UserMessageQueued { .. }
    ));

    let second_ctx = ctx.clone();
    let second = tokio::spawn(async move {
        let mut state = state;
        handle_request(
            Request::SendUserMessage {
                text: "second turn".into(),
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs: Vec::new(),
                forced_skill: None,
            },
            &mut state,
            &second_ctx,
        )
        .await
    });
    let second_work = tokio::time::timeout(std::time::Duration::from_secs(2), work_rx.recv())
        .await
        .expect("second turn delivered")
        .expect("second turn work");
    let SessionWork::UserMessage {
        submission,
        respond_to,
    } = second_work
    else {
        panic!("expected second user message work");
    };
    assert_eq!(submission.text, "second turn");
    assert_eq!(
        ctx.db
            .current_session_goal(session_id, false)
            .unwrap()
            .expect("next turn reads paused goal")
            .status,
        crate::db::session_goals::GoalStatus::Paused
    );
    let item = proto::QueueItem {
        id: Uuid::new_v4(),
        status: proto::QueueItemStatus::Queued,
        text: submission.text.clone(),
        display_text: None,
        target: proto::QueueTarget::default(),
    };
    respond_to.send((item.clone(), vec![item])).unwrap();
    assert!(matches!(
        second
            .await
            .expect("second turn joins")
            .expect("second turn completes"),
        Response::UserMessageQueued { .. }
    ));
}

#[test]
fn new_session_state_requests_are_classified() {
    let session_id = Uuid::from_u128(42);
    let state = owner_state();
    let cases = [
        (
            Request::GoalStatus { session_id },
            "goal_status",
            Some(session_id),
            false,
            None,
        ),
        (
            Request::SetGoalStatus {
                session_id,
                status: proto::GoalStatus::Paused,
            },
            "set_goal_status",
            Some(session_id),
            true,
            None,
        ),
        (
            Request::ClearGoal { session_id },
            "clear_goal",
            Some(session_id),
            true,
            None,
        ),
        (
            Request::ListAssistants,
            "list_assistants",
            None,
            false,
            None,
        ),
        (
            Request::CreateAssistantSession {
                name: "helper".into(),
                project_root: "/repo".into(),
                no_sandbox: false,
                env_snapshot: None,
            },
            "create_assistant_session",
            None,
            true,
            None,
        ),
        (
            Request::StatsRollup {
                project_id: None,
                range: proto::StatsRange::AllTime,
                by_role: false,
            },
            "stats_rollup",
            None,
            false,
            None,
        ),
        (
            Request::ExportSessionData {
                session_id,
                kind: proto::ExportSessionKind::TranscriptJson,
                include_generated_artifacts: false,
                include_sensitive: false,
            },
            "export_session_data",
            Some(session_id),
            false,
            None,
        ),
        (
            Request::AutoTitle { session_id },
            "auto_title",
            Some(session_id),
            true,
            None,
        ),
        (
            Request::Curator {
                project_root: "/repo".into(),
                action: proto::CuratorAction::Status,
            },
            "curator",
            None,
            true,
            Some("/repo"),
        ),
    ];

    for (request, kind, session, mutating, audit_path) in cases {
        assert_eq!(principal::request_kind(&request), kind);
        assert_eq!(request_session_id(&request, &state), session, "{kind}");
        assert_eq!(is_remote_mutating_request(&request), mutating, "{kind}");
        assert_eq!(
            request_audit_path(&request).as_deref(),
            audit_path,
            "{kind}"
        );
    }
}

#[test]
fn new_session_state_requests_enforce_authorization() {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    let session_id = session.session_id;
    let state = remote_state_with_grants(Vec::new());
    let requests = [
        Request::GoalStatus { session_id },
        Request::SetGoalStatus {
            session_id,
            status: proto::GoalStatus::Paused,
        },
        Request::ClearGoal { session_id },
        Request::ListAssistants,
        Request::CreateAssistantSession {
            name: "helper".into(),
            project_root: "/repo".into(),
            no_sandbox: false,
            env_snapshot: None,
        },
        Request::StatsRollup {
            project_id: None,
            range: proto::StatsRange::AllTime,
            by_role: false,
        },
        Request::ExportSessionData {
            session_id,
            kind: proto::ExportSessionKind::TranscriptJson,
            include_generated_artifacts: false,
            include_sensitive: false,
        },
        Request::AutoTitle { session_id },
        Request::Curator {
            project_root: "/repo".into(),
            action: proto::CuratorAction::Status,
        },
    ];

    for request in requests {
        let kind = principal::request_kind(&request);
        let err = authorize_request(&request, &state, &ctx)
            .err()
            .unwrap_or_else(|| panic!("{kind} unexpectedly authorized"));
        assert_eq!(err.code, ErrorCode::Authorization, "{kind}");
    }
}

#[tokio::test]
async fn stats_rpc_returns_rollup() {
    let ctx = test_ctx();
    let mut state = owner_state();
    let response = handle_request(
        Request::StatsRollup {
            project_id: Some("project-1".to_string()),
            range: proto::StatsRange::Last7Days,
            by_role: true,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("stats rollup");
    let Response::StatsRollup { rollup } = response else {
        panic!("expected StatsRollup response");
    };
    assert_eq!(rollup.project_id.as_deref(), Some("project-1"));
    assert_eq!(rollup.range, "7d");
    assert!(rollup.tokens.by_model.is_empty());
    assert!(matches!(rollup.tokens.by_role, Some(rows) if rows.is_empty()));
    assert!(rollup.recovery.by_model.is_empty());
    assert!(rollup.language.languages.is_empty());
}

#[tokio::test]
async fn stats_rollup_runs_off_request_loop() {
    let ctx = test_ctx();
    let session = ctx
        .db
        .create_session("project-1", "/repo", "Build")
        .unwrap();
    ctx.db
        .insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
            call_id: Uuid::new_v4(),
            session_id: session.session_id,
            project_id: "project-1".to_string(),
            project_root: "/repo".to_string(),
            model: "gpt-5".to_string(),
            provider: "openai".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            input_tokens: 10,
            output_tokens: 20,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility: false,
        })
        .unwrap();
    let mut state = owner_state();

    let response = handle_request(
        Request::StatsRollup {
            project_id: Some("project-1".to_string()),
            range: proto::StatsRange::AllTime,
            by_role: true,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("stats rollup");

    let Response::StatsRollup { rollup } = response else {
        panic!("expected StatsRollup response");
    };
    assert_eq!(rollup.project_id.as_deref(), Some("project-1"));
    assert_eq!(rollup.range, "all");
    assert_eq!(rollup.tokens.by_model.len(), 1);
    assert_eq!(rollup.tokens.by_model[0].model, "gpt-5");
    assert_eq!(rollup.tokens.by_model[0].provider, "openai");
    assert_eq!(rollup.tokens.by_model[0].input_tokens, 10);
    assert_eq!(rollup.tokens.by_model[0].output_tokens, 20);
}

#[tokio::test]
async fn assistant_rpc_creates_session_via_registry() {
    let ctx = test_ctx();
    let assistant_home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    create_test_assistant(&ctx, &assistant_home, "helper-bot");
    let mut state = owner_state();

    let response = handle_request(Request::ListAssistants, &mut state, &ctx)
        .await
        .expect("list assistants");
    let Response::Assistants { assistants } = response else {
        panic!("expected Assistants response");
    };
    assert_eq!(assistants.len(), 1);
    assert_eq!(assistants[0].name, "helper-bot");

    let response = handle_request(
        Request::CreateAssistantSession {
            name: "helper-bot".into(),
            project_root: project.path().to_string_lossy().into_owned(),
            no_sandbox: false,
            env_snapshot: None,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("create assistant session");
    let Response::AssistantSessionCreated { session } = response else {
        panic!("expected AssistantSessionCreated response");
    };
    assert_eq!(session.assistant_name, "helper-bot");
    assert_eq!(session.active_agent, "helper-bot");
    assert!(
        ctx.registry
            .active_session_ids()
            .contains(&session.session_id),
        "created assistant session is live in the registry"
    );
    assert!(
        ctx.db.get_session(session.session_id).unwrap().is_none(),
        "created assistant session is deferred until first user message"
    );
}

#[tokio::test]
async fn assistant_session_creation_is_atomic() {
    let ctx = test_ctx();
    let assistant_home = tempfile::tempdir().unwrap();
    let untrusted_project = tempfile::tempdir().unwrap();
    create_test_assistant(&ctx, &assistant_home, "helper-bot");
    let mut state = owner_state();

    let err = handle_request(
        Request::CreateAssistantSession {
            name: "helper-bot".into(),
            project_root: untrusted_project.path().to_string_lossy().into_owned(),
            no_sandbox: false,
            env_snapshot: None,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("untrusted workspace rejects assistant session creation");

    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(
        ctx.registry.active_session_ids().is_empty(),
        "failed assistant session creation must not register a live worker"
    );
    assert!(
        ctx.db.list_sessions(false, 100).unwrap().is_empty(),
        "failed assistant session creation must not persist a session row"
    );
}

#[tokio::test]
async fn auto_title_rpc_generates_title() {
    let project = tempfile::tempdir().unwrap();
    let url = auto_title_model_server(Some("Codex Model Fetch".to_string())).await;
    let ctx = test_ctx_with_config_source(auto_title_config_source(&url));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", project.path().to_str().unwrap(), "Build")
        .unwrap();
    ctx.db
        .insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "fetch the codex model list"}),
        )
        .unwrap();
    let mut state = owner_state();

    let response = handle_request(
        Request::AutoTitle {
            session_id: session.session_id,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("auto title");

    let Response::AutoTitle { session_id, title } = response else {
        panic!("expected AutoTitle response");
    };
    assert_eq!(session_id, session.session_id);
    assert_eq!(title, "codex-model-fetch");
    let row = ctx.db.get_session(session.session_id).unwrap().unwrap();
    assert_eq!(row.title.as_deref(), Some("codex-model-fetch"));
    assert!(!row.user_renamed);
}

#[tokio::test]
async fn auto_title_failure_leaves_session_unrenamed() {
    let project = tempfile::tempdir().unwrap();
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
    ));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", project.path().to_str().unwrap(), "Build")
        .unwrap();
    let mut state = owner_state();

    let err = handle_request(
        Request::AutoTitle {
            session_id: session.session_id,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("missing utility model rejects");

    assert_eq!(err.code, ErrorCode::BadRequest);
    let row = ctx.db.get_session(session.session_id).unwrap().unwrap();
    assert!(row.title.is_none());
    assert!(!row.user_renamed);
}

#[tokio::test]
async fn concurrent_auto_title_second_attempt_is_rejected() {
    let project = tempfile::tempdir().unwrap();
    let url = auto_title_model_server(Some("Concurrent Title".to_string())).await;
    let ctx = test_ctx_with_config_source(auto_title_config_source(&url));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", project.path().to_str().unwrap(), "Build")
        .unwrap();
    let mut first_state = owner_state();
    let mut second_state = owner_state();
    let first_request = Request::AutoTitle {
        session_id: session.session_id,
    };
    let second_request = first_request.clone();

    let (first, second) = tokio::join!(
        handle_request(first_request, &mut first_state, &ctx),
        handle_request(second_request, &mut second_state, &ctx),
    );

    let mut successes = 0;
    let mut rejections = 0;
    for result in [first, second] {
        match result {
            Ok(Response::AutoTitle { title, .. }) => {
                successes += 1;
                assert_eq!(title, "concurrent-title");
            }
            Err(err)
                if err.code == ErrorCode::BadRequest
                    && err.message.contains("already has a title") =>
            {
                rejections += 1;
            }
            other => panic!("unexpected auto-title result: {other:?}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(rejections, 1);
    let row = ctx.db.get_session(session.session_id).unwrap().unwrap();
    assert_eq!(row.title.as_deref(), Some("concurrent-title"));
    assert!(!row.user_renamed);
}

#[tokio::test]
async fn export_rpc_returns_redacted_data() {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    let call_id = Uuid::new_v4().to_string();
    ctx.db
        .insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "hello [redacted]"}),
        )
        .unwrap();
    ctx.db
        .insert_inference_request(
            &call_id,
            session.session_id,
            &serde_json::json!({
                "model": "m",
                "system": "visible [redacted]",
                "tools": [],
                "history": []
            }),
            crate::db::session_log::InferenceRequestStatus::Completed,
        )
        .unwrap();
    ctx.db
        .insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some("Build"),
            Some(&call_id),
            &serde_json::json!({}),
        )
        .unwrap();
    let mut state = owner_state();

    let response = handle_request(
        Request::ExportSessionData {
            session_id: session.session_id,
            kind: proto::ExportSessionKind::TranscriptJson,
            include_generated_artifacts: false,
            include_sensitive: false,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("transcript export");
    let Response::ExportSessionData { data } = response else {
        panic!("expected ExportSessionData response");
    };
    assert_eq!(data.kind, proto::ExportSessionKind::TranscriptJson);
    assert_eq!(data.filename_extension, "json");
    assert!(data.redacted);
    let transcript = base64::engine::general_purpose::STANDARD
        .decode(data.content_base64.as_bytes())
        .unwrap();
    let transcript_json: serde_json::Value = serde_json::from_slice(&transcript).unwrap();
    assert!(transcript_json.to_string().contains("[redacted]"));
    assert!(!transcript_json.to_string().contains("sk-"));

    let response = handle_request(
        Request::ExportSessionData {
            session_id: session.session_id,
            kind: proto::ExportSessionKind::DebugBundle,
            include_generated_artifacts: false,
            include_sensitive: false,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("debug bundle export");
    let Response::ExportSessionData { data } = response else {
        panic!("expected ExportSessionData response");
    };
    assert_eq!(data.kind, proto::ExportSessionKind::DebugBundle);
    assert_eq!(data.filename_extension, "zip");
    assert_eq!(data.mime, "application/zip");
    assert_eq!(data.session_count, Some(1));
    assert_eq!(
        data.byte_len,
        base64::engine::general_purpose::STANDARD
            .decode(data.content_base64.as_bytes())
            .unwrap()
            .len()
    );
    assert!(data.redacted);
}

#[tokio::test]
async fn curator_rpc_performs_curation() {
    let project = tempfile::tempdir().unwrap();
    let skill_root = project.path().join(".agents").join("skills");
    write_curator_skill(&skill_root, "curated");
    let ctx = test_ctx_with_config_source(curator_config_source(&skill_root));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let mut state = owner_state();

    let response = handle_request(
        Request::Curator {
            project_root: project.path().to_string_lossy().into_owned(),
            action: proto::CuratorAction::Status,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("curator status");
    let Response::Curator {
        result: proto::CuratorResult::Status { status },
    } = response
    else {
        panic!("expected curator status");
    };
    assert_eq!(status.skills.len(), 1);
    assert_eq!(status.skills[0].name, "curated");

    let response = handle_request(
        Request::Curator {
            project_root: project.path().to_string_lossy().into_owned(),
            action: proto::CuratorAction::Run {
                dry_run: true,
                consolidate: false,
            },
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("curator dry run");
    let Response::Curator {
        result: proto::CuratorResult::Run { report },
    } = response
    else {
        panic!("expected curator run");
    };
    assert!(report.dry_run);
    assert_eq!(report.scanned, 1);

    handle_request(
        Request::Curator {
            project_root: project.path().to_string_lossy().into_owned(),
            action: proto::CuratorAction::Pin {
                name: "curated".to_string(),
            },
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("curator pin");
    assert!(
        ctx.db
            .get_skill_usage("curated")
            .unwrap()
            .expect("skill usage row")
            .pinned
    );
}

#[tokio::test]
async fn curator_rpc_failure_leaves_skills_unchanged() {
    let project = tempfile::tempdir().unwrap();
    let skill_root = project.path().join(".agents").join("skills");
    write_curator_skill(&skill_root, "curated");
    let ctx = test_ctx_with_config_source(curator_config_source(&skill_root));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let mut state = owner_state();

    handle_request(
        Request::Curator {
            project_root: project.path().to_string_lossy().into_owned(),
            action: proto::CuratorAction::Status,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("seed curator status");
    let before = ctx.db.list_skill_usage().unwrap();

    let err = handle_request(
        Request::Curator {
            project_root: project.path().to_string_lossy().into_owned(),
            action: proto::CuratorAction::Pin {
                name: "missing".to_string(),
            },
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("unknown skill rejects");

    assert_eq!(err.code, ErrorCode::BadRequest);
    assert_eq!(ctx.db.list_skill_usage().unwrap(), before);
    assert!(skill_root.join("curated").join("SKILL.md").is_file());
}

#[test]
fn boundary_owner_gets_raw_non_owner_gets_scrubbed_from_same_envelope() {
    let table = table_for("client-boundary-secret");
    let event = proto::Event::AssistantText {
        session_id: Uuid::new_v4(),
        agent: "Build".to_string(),
        text: "visible client-boundary-secret".to_string(),
        reasoning: String::new(),
        seq: None,
    };
    let envelope = EventEnvelope {
        event: event.clone(),
        redact: table,
    };

    let owner = scrub_event_for_principal(&ClientPrincipal::owner(), envelope.clone()).unwrap();
    assert_eq!(
        serde_json::to_string(&owner).unwrap(),
        serde_json::to_string(&event).unwrap()
    );
    let scrubbed = scrub_event_for_principal(&remote_principal(), envelope).unwrap();
    let proto::Event::AssistantText { text, .. } = scrubbed else {
        panic!("expected AssistantText")
    };
    assert_eq!(text, "visible [redacted]");
}

#[test]
fn boundary_scrubs_streaming_deltas_for_non_owner() {
    let table = table_for("stream-secret");
    for event in [
        proto::Event::AssistantTextDelta {
            session_id: Uuid::new_v4(),
            agent: "Build".to_string(),
            delta: "token stream-secret".to_string(),
        },
        proto::Event::ReasoningDelta {
            session_id: Uuid::new_v4(),
            agent: "Build".to_string(),
            delta: "thought stream-secret".to_string(),
        },
    ] {
        let scrubbed = scrub_event_for_principal(
            &remote_principal(),
            EventEnvelope {
                event,
                redact: table.clone(),
            },
        )
        .unwrap();
        let rendered = serde_json::to_string(&scrubbed).unwrap();
        assert!(!rendered.contains("stream-secret"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }
}

#[test]
fn boundary_scrubs_nested_json_text_for_non_owner() {
    let table = table_for("nested-secret");
    let event = proto::Event::ToolStart {
        session_id: Uuid::new_v4(),
        agent: "Build".to_string(),
        call_id: "call-1".to_string(),
        tool: "bash".to_string(),
        args: serde_json::json!({ "sidecar": { "text": "nested-secret" } }),
    };
    let scrubbed = scrub_event_for_principal(
        &remote_principal(),
        EventEnvelope {
            event,
            redact: table,
        },
    )
    .unwrap();
    let rendered = serde_json::to_string(&scrubbed).unwrap();
    assert!(!rendered.contains("nested-secret"), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
}

#[test]
fn boundary_uses_emit_time_table_not_later_table() {
    let emit_table = table_for("emit-secret");
    let _later_table = table_for("later-secret");
    let event = proto::Event::AssistantTextDelta {
        session_id: Uuid::new_v4(),
        agent: "Build".to_string(),
        delta: "emit-secret later-secret".to_string(),
    };
    let scrubbed = scrub_event_for_principal(
        &remote_principal(),
        EventEnvelope {
            event,
            redact: emit_table,
        },
    )
    .unwrap();
    let proto::Event::AssistantTextDelta { delta, .. } = scrubbed else {
        panic!("expected AssistantTextDelta")
    };
    assert_eq!(delta, "[redacted] later-secret");
}

#[test]
fn session_and_global_events_use_their_own_tables() {
    let session_id = Uuid::new_v4();
    let session_event = proto::Event::Notice {
        session_id,
        text: "session-secret global-secret".to_string(),
    };
    let global_event = proto::Event::LspNotice {
        text: "session-secret global-secret".to_string(),
    };

    let scrubbed_session = scrub_event_for_principal(
        &remote_principal(),
        EventEnvelope {
            event: session_event,
            redact: table_for("session-secret"),
        },
    )
    .unwrap();
    let scrubbed_global = scrub_event_for_principal(
        &remote_principal(),
        EventEnvelope {
            event: global_event,
            redact: table_for("global-secret"),
        },
    )
    .unwrap();

    let proto::Event::Notice { text, .. } = scrubbed_session else {
        panic!("expected Notice")
    };
    assert_eq!(text, "[redacted] global-secret");
    let proto::Event::LspNotice { text } = scrubbed_global else {
        panic!("expected LspNotice")
    };
    assert_eq!(text, "session-secret [redacted]");
}

#[test]
fn attach_history_is_scrubbed_only_for_non_owner() {
    let table = table_for("history-secret");
    let history = vec![proto::HistoryEntry::ToolCall {
        seq: 1,
        agent: "Build".to_string(),
        call_id: "call-1".to_string(),
        parent_call_id: None,
        parent_child_index: None,
        tool: "bash".to_string(),
        mcp_server: None,
        mcp_builtin: None,
        mcp_kind: None,
        original_input: serde_json::json!({ "cmd": "echo history-secret" }),
        wire_input: serde_json::json!({ "cmd": "echo history-secret" }),
        recovery_kind: None,
        recovery_stage: None,
        output: "history-secret".to_string(),
        hard_fail: false,
        truncated: false,
        hint: Some("history-secret".to_string()),
    }];

    let owner = scrub_history_for_principal(&ClientPrincipal::owner(), history.clone(), &table);
    assert_eq!(
        serde_json::to_string(&owner).unwrap(),
        serde_json::to_string(&history).unwrap()
    );
    let remote = scrub_history_for_principal(&remote_principal(), history, &table);
    let rendered = serde_json::to_string(&remote).unwrap();
    assert!(!rendered.contains("history-secret"), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
}

/// Stub config seam (`daemon-trust-test-isolation.md`): a minimal
/// in-memory providers config (one loopback provider with an active
/// model, mirroring the session-worker tests' `write_model_config`) so
/// attach resolves a model deterministically regardless of what lives in
/// the developer's `~/.config/cockpit`. Tests that want specific
/// provider/model configs inject them through
/// [`test_ctx_with_config_source`] instead.
fn stub_config_source() -> crate::daemon::config_source::ConfigSource {
    use crate::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry};

    let mut providers = std::collections::BTreeMap::new();
    providers.insert(
        "lmstudio".to_string(),
        ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            models: vec![ModelEntry {
                id: "stub-model".to_string(),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    crate::daemon::config_source::ConfigSource::fixed(
        crate::config::providers::ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".to_string(),
                model: "stub-model".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..crate::config::providers::ProvidersConfig::default()
        },
        crate::config::extended::ExtendedConfig::default(),
    )
}

fn test_ctx() -> Arc<DaemonContext> {
    test_ctx_with_config_source(stub_config_source())
}

fn test_ctx_with_config_source(
    config_source: crate::daemon::config_source::ConfigSource,
) -> Arc<DaemonContext> {
    let db = Db::open_in_memory().expect("in-memory db");
    let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
    let paths = DaemonPaths {
        socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
        pid_file: std::path::PathBuf::from("/tmp/cockpit-test.pid"),
        ephemeral: true,
    };
    Arc::new(DaemonContext::new(
        db,
        locks,
        paths,
        crate::daemon::terminal::test_host_factory(),
        config_source,
    ))
}

fn curator_config_source(skill_root: &Path) -> crate::daemon::config_source::ConfigSource {
    let extended = crate::config::extended::ExtendedConfig {
        skills: crate::config::extended::SkillsConfig {
            scan_dirs: vec![skill_root.to_string_lossy().into_owned()],
            ..crate::config::extended::SkillsConfig::default()
        },
        ..crate::config::extended::ExtendedConfig::default()
    };
    crate::daemon::config_source::ConfigSource::fixed(
        crate::config::providers::ProvidersConfig::default(),
        extended,
    )
}

fn auto_title_config_source(base_url: &str) -> crate::daemon::config_source::ConfigSource {
    use crate::config::providers::ProviderEntry;

    let extended = crate::config::extended::ExtendedConfig {
        utility_model: Some("p:m".to_string()),
        ..crate::config::extended::ExtendedConfig::default()
    };
    let mut providers = crate::config::providers::ProvidersConfig::default();
    providers.providers.insert(
        "p".to_string(),
        ProviderEntry {
            url: base_url.to_string(),
            ..ProviderEntry::default()
        },
    );
    crate::daemon::config_source::ConfigSource::fixed(providers, extended)
}

async fn auto_title_model_server(content: Option<String>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                let s = String::from_utf8_lossy(&buf);
                if let Some(idx) = s.find("\r\n\r\n") {
                    let header = &s[..idx];
                    let content_len = header
                        .lines()
                        .find_map(|line| {
                            let line = line.to_ascii_lowercase();
                            line.strip_prefix("content-length:")
                                .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= idx + 4 + content_len {
                        break;
                    }
                }
            }
            let Some(content) = &content else {
                let resp = "HTTP/1.1 500 Internal Server Error\r\n\
                                Content-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes()).await;
                continue;
            };
            let escaped = content
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r");
            let payload = format!(
                "{{\"id\":\"c\",\"object\":\"chat.completion\",\"created\":0,\
                     \"model\":\"m\",\"system_fingerprint\":null,\
                     \"choices\":[{{\"index\":0,\"message\":{{\"role\":\"assistant\",\
                     \"content\":[{{\"type\":\"text\",\"text\":\"{escaped}\"}}]}},\
                     \"logprobs\":null,\"finish_reason\":\"stop\"}}],\
                     \"usage\":{{\"prompt_tokens\":1,\"total_tokens\":2,\
                     \"prompt_tokens_details\":{{\"cached_tokens\":0}}}}}}"
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        }
    });
    format!("http://{addr}/v1")
}

fn write_curator_skill(skill_root: &Path, name: &str) {
    let dir = skill_root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: test skill\n---\n\nUse it.\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join(".cockpit-provenance.json"),
        r#"{
  "created_origin": "background_review",
  "writes": [{"action":"create","origin":"background_review","unix_seconds":1}],
  "pinned": false
}"#,
    )
    .unwrap();
}

fn persistent_test_ctx() -> Arc<DaemonContext> {
    let db = Db::open_in_memory().expect("in-memory db");
    let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
    let paths = DaemonPaths {
        socket: std::path::PathBuf::from("/tmp/cockpit-persistent-test.sock"),
        pid_file: std::path::PathBuf::from("/tmp/cockpit-persistent-test.pid"),
        ephemeral: false,
    };
    Arc::new(DaemonContext::new(
        db,
        locks,
        paths,
        crate::daemon::terminal::test_host_factory(),
        stub_config_source(),
    ))
}

fn persistent_test_ctx_with_credential_path(path: std::path::PathBuf) -> Arc<DaemonContext> {
    let db = Db::open_in_memory().expect("in-memory db");
    let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
    let paths = DaemonPaths {
        socket: std::path::PathBuf::from("/tmp/cockpit-persistent-test.sock"),
        pid_file: std::path::PathBuf::from("/tmp/cockpit-persistent-test.pid"),
        ephemeral: false,
    };
    Arc::new(
        DaemonContext::new(
            db,
            locks,
            paths,
            crate::daemon::terminal::test_host_factory(),
            stub_config_source(),
        )
        .with_credential_store_path(path),
    )
}

fn test_ctx_with_credential_path(path: std::path::PathBuf) -> Arc<DaemonContext> {
    let db = Db::open_in_memory().expect("in-memory db");
    let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
    let paths = DaemonPaths {
        socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
        pid_file: std::path::PathBuf::from("/tmp/cockpit-test.pid"),
        ephemeral: true,
    };
    Arc::new(
        DaemonContext::new(
            db,
            locks,
            paths,
            crate::daemon::terminal::test_host_factory(),
            stub_config_source(),
        )
        .with_credential_store_path(path),
    )
}

fn remote_state_with_grants(
    grants: Vec<crate::daemon::principal::PrincipalGrant>,
) -> MutableClientState {
    MutableClientState {
        principal: ClientPrincipal::Remote(crate::daemon::principal::RemotePrincipal {
            user_id: "user-1".into(),
            grants,
        }),
        attached: None,
        pending_replay: Vec::new(),
        pending_uploads: HashMap::new(),
        ready_attachments: HashMap::new(),
        upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
        upload_limits: AttachmentUploadLimits::default(),
        terminal_views: HashSet::new(),
        terminal_host: test_terminal_host(),
    }
}

fn project_files_grant(root: &Path) -> crate::daemon::principal::PrincipalGrant {
    crate::daemon::principal::PrincipalGrant {
        scope: crate::daemon::principal::PrincipalScope::ProjectFiles,
        project_root: Some(root.to_string_lossy().into_owned()),
    }
}

fn terminal_grant() -> crate::daemon::principal::PrincipalGrant {
    crate::daemon::principal::PrincipalGrant {
        scope: crate::daemon::principal::PrincipalScope::Terminal,
        project_root: None,
    }
}

fn owner_state() -> MutableClientState {
    MutableClientState {
        principal: ClientPrincipal::owner(),
        attached: None,
        pending_replay: Vec::new(),
        pending_uploads: HashMap::new(),
        ready_attachments: HashMap::new(),
        upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
        upload_limits: AttachmentUploadLimits::default(),
        terminal_views: HashSet::new(),
        terminal_host: test_terminal_host(),
    }
}

fn flycockpit_credential() -> crate::auth::flycockpit::StoredFlycockpitCredential {
    crate::auth::flycockpit::StoredFlycockpitCredential {
        server_url: "https://app.example.test".to_string(),
        instance_id: "inst-1".to_string(),
        instance_token: "fci_instance_secret_rpc".to_string(),
        account: crate::auth::flycockpit::AccountInfo {
            user_id: "user-1".to_string(),
            email: "user@example.test".to_string(),
        },
        display_name: Some("Devbox".to_string()),
        relay_choice: None,
    }
}

#[tokio::test]
async fn persistent_daemon_stores_flycockpit_credential_and_wakes_connector() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let credential_path = tmp.path().join("state/cockpit/credentials.json");
    let ctx = persistent_test_ctx_with_credential_path(credential_path.clone());
    let credential = flycockpit_credential();
    let mut state = owner_state();
    let mut wake_rx = ctx.connector_wake_rx();

    let debug = format!(
        "{:?}",
        Request::StoreFlycockpitCredential {
            credential: credential.clone(),
        }
    );
    assert!(!debug.contains(&credential.instance_token));
    assert!(debug.contains("<redacted>"));

    let response = handle_request(
        Request::StoreFlycockpitCredential {
            credential: credential.clone(),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("credential store succeeds");
    assert!(matches!(response, Response::Ack));
    tokio::time::timeout(Duration::from_millis(100), wake_rx.changed())
        .await
        .expect("connector wake delivered")
        .expect("wake sender alive");

    let stored =
        crate::auth::flycockpit::load_credential_from_path(credential_path.clone()).unwrap();
    assert_eq!(stored, credential);

    #[cfg(unix)]
    {
        let store = crate::credentials::CredentialStore::open(credential_path.clone()).unwrap();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let table = crate::redact::RedactionTable::build(
        &crate::config::extended::RedactConfig::default(),
        tmp.path(),
    )
    .unwrap();
    let scrubbed = table.scrub("token=fci_instance_secret_rpc");
    assert!(!scrubbed.contains("fci_instance_secret_rpc"));
}

#[tokio::test]
async fn persistent_daemon_clears_flycockpit_credential_and_wakes_connector() {
    let tmp = tempfile::tempdir().unwrap();
    let credential_path = tmp.path().join("state/cockpit/credentials.json");
    let ctx = persistent_test_ctx_with_credential_path(credential_path.clone());
    crate::auth::flycockpit::store_credential_at_path(
        credential_path.clone(),
        &flycockpit_credential(),
    )
    .unwrap();
    let mut state = owner_state();
    let mut wake_rx = ctx.connector_wake_rx();

    let response = handle_request(Request::ClearFlycockpitCredential, &mut state, &ctx)
        .await
        .expect("credential clear succeeds");
    assert!(matches!(response, Response::Ack));
    tokio::time::timeout(Duration::from_millis(100), wake_rx.changed())
        .await
        .expect("connector wake delivered")
        .expect("wake sender alive");
    assert!(crate::auth::flycockpit::load_credential_from_path(credential_path).is_err());
}

#[tokio::test]
async fn ephemeral_daemon_rejects_flycockpit_credential_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let credential_path = tmp.path().join("state/cockpit/credentials.json");
    let ctx = test_ctx_with_credential_path(credential_path.clone());
    let mut state = owner_state();
    let err = handle_request(
        Request::StoreFlycockpitCredential {
            credential: flycockpit_credential(),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("ephemeral daemon must reject credential writes");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("ephemeral daemons"));

    let err = handle_request(Request::ClearFlycockpitCredential, &mut state, &ctx)
        .await
        .expect_err("ephemeral daemon must reject credential clears");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(crate::auth::flycockpit::load_credential_from_path(credential_path).is_err());
}

#[tokio::test]
async fn fs_requests_require_project_files_scope_for_matching_root() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let root_a = tmp.path().join("a");
    let root_b = tmp.path().join("b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    ctx.db
        .set_workspace_trust(
            &root_a,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    ctx.db
        .set_workspace_trust(
            &root_b,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    std::fs::write(root_a.join("readme.md"), "ok").unwrap();
    std::fs::write(root_b.join("readme.md"), "no").unwrap();

    let mut no_scope = remote_state_with_grants(Vec::new());
    let err = handle_request(
        Request::FsRead {
            project_root: root_a.to_string_lossy().into_owned(),
            path: "readme.md".into(),
            base64: false,
        },
        &mut no_scope,
        &ctx,
    )
    .await
    .expect_err("missing project_files scope must be denied");
    assert_eq!(err.code, ErrorCode::Authorization);

    let mut root_a_scope = remote_state_with_grants(vec![project_files_grant(&root_a)]);
    let err = handle_request(
        Request::FsRead {
            project_root: root_b.to_string_lossy().into_owned(),
            path: "readme.md".into(),
            base64: false,
        },
        &mut root_a_scope,
        &ctx,
    )
    .await
    .expect_err("project_files scope must not cross roots");
    assert_eq!(err.code, ErrorCode::Authorization);

    let response = handle_request(
        Request::FsRead {
            project_root: root_a.to_string_lossy().into_owned(),
            path: "readme.md".into(),
            base64: false,
        },
        &mut root_a_scope,
        &ctx,
    )
    .await
    .expect("matching scope reads");
    match response {
        Response::FsRead { content, .. } => assert_eq!(content.as_deref(), Some("ok")),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn terminal_requests_require_terminal_scope_and_audit_open_close() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();

    let mut no_scope = remote_state_with_grants(Vec::new());
    let err = handle_request(
        Request::OpenTerminal {
            cwd: Some(tmp.path().to_string_lossy().into_owned()),
            cols: 80,
            rows: 24,
        },
        &mut no_scope,
        &ctx,
    )
    .await
    .expect_err("missing terminal scope must be denied");
    assert_eq!(err.code, ErrorCode::Authorization);

    let mut terminal_scope = remote_state_with_grants(vec![terminal_grant()]);
    let response = handle_request(
        Request::OpenTerminal {
            cwd: Some(tmp.path().to_string_lossy().into_owned()),
            cols: 80,
            rows: 24,
        },
        &mut terminal_scope,
        &ctx,
    )
    .await
    .expect("terminal scope opens a PTY");
    let terminal_id = match response {
        Response::TerminalOpened { terminal_id, .. } => terminal_id,
        other => panic!("unexpected response: {other:?}"),
    };
    assert!(terminal_scope.terminal_views.contains(&terminal_id));

    handle_request(
        Request::CloseTerminal { terminal_id },
        &mut terminal_scope,
        &ctx,
    )
    .await
    .expect("close succeeds");

    let rows = ctx.db.list_remote_audit().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].request_kind, "open_terminal");
    assert_eq!(rows[0].verdict, "denied");
    assert_eq!(rows[1].request_kind, "open_terminal");
    assert_eq!(rows[1].verdict, "allowed");
    assert_eq!(rows[2].request_kind, "close_terminal");
    assert_eq!(rows[2].verdict, "allowed");
}

#[tokio::test]
async fn remote_fs_write_hash_mismatch_and_lock_conflict_are_typed() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let path = root.join("file.txt");
    std::fs::write(&path, "current").unwrap();
    let mut state = remote_state_with_grants(vec![project_files_grant(root)]);

    let err = handle_request(
        Request::FsWrite {
            project_root: root.to_string_lossy().into_owned(),
            path: "file.txt".into(),
            content: "next".into(),
            base_hash: Some("wrong".into()),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("stale hash must be rejected");
    assert_eq!(err.code, ErrorCode::HashMismatch);

    let session = ctx
        .db
        .create_session("proj", &root.to_string_lossy(), "Build")
        .unwrap();
    ctx.registry
        .locks()
        .acquire(&path, "builder", session.session_id)
        .unwrap();
    let err = handle_request(
        Request::FsWrite {
            project_root: root.to_string_lossy().into_owned(),
            path: "file.txt".into(),
            content: "next".into(),
            base_hash: None,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("active agent lock must conflict");
    assert_eq!(err.code, ErrorCode::LockConflict);
}

#[tokio::test]
async fn remote_fs_mutations_are_audited_with_path() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let mut state = remote_state_with_grants(vec![project_files_grant(root)]);

    let response = handle_request(
        Request::FsWrite {
            project_root: root.to_string_lossy().into_owned(),
            path: "src/main.rs".into(),
            content: "fn main() {}\n".into(),
            base_hash: None,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("write succeeds");
    assert!(matches!(response, Response::FsWrite { .. }));

    let rows = ctx.db.list_remote_audit().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].principal, "flycockpit:user-1");
    assert_eq!(rows[0].request_kind, "fs_write");
    assert_eq!(rows[0].verdict, "allowed");
    assert_eq!(rows[0].path.as_deref(), Some("src/main.rs"));
}

#[tokio::test]
async fn resource_scheduler_is_shared_only_for_persistent_daemons() {
    let persistent_db = Db::open_in_memory().expect("in-memory db");
    let persistent_locks = Arc::new(LockManager::from_db(persistent_db.clone()).expect("locks"));
    let persistent = DaemonContext::new(
        persistent_db,
        persistent_locks,
        DaemonPaths {
            socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
            pid_file: std::path::PathBuf::from("/tmp/cockpit-test.pid"),
            ephemeral: false,
        },
        crate::daemon::terminal::test_host_factory(),
        stub_config_source(),
    );
    assert!(persistent.registry.resource_scheduler().is_some());

    let ephemeral_db = Db::open_in_memory().expect("in-memory db");
    let ephemeral_locks = Arc::new(LockManager::from_db(ephemeral_db.clone()).expect("locks"));
    let ephemeral = DaemonContext::new(
        ephemeral_db,
        ephemeral_locks,
        DaemonPaths {
            socket: std::path::PathBuf::from("/tmp/cockpit-eph-test.sock"),
            pid_file: std::path::PathBuf::from("/tmp/cockpit-eph-test.pid"),
            ephemeral: true,
        },
        crate::daemon::terminal::test_host_factory(),
        stub_config_source(),
    );
    assert!(ephemeral.registry.resource_scheduler().is_none());
}

#[tokio::test]
async fn promote_resource_request_moves_queued_request_to_front() {
    let ctx = persistent_test_ctx();
    let scheduler = ctx
        .registry
        .resource_scheduler()
        .expect("persistent scheduler");
    let running = scheduler
        .submit(
            crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
            ),
        )
        .expect("running ticket");
    let _queued_a = scheduler
        .submit(
            crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
            ),
        )
        .expect("queued ticket");
    let queued_b = scheduler
        .submit(
            crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
            ),
        )
        .expect("queued ticket");
    let before = scheduler.snapshot();
    assert_eq!(before.running[0].id, running.request_id());
    assert_eq!(before.queued[1].id, queued_b.request_id());

    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(
        Request::PromoteResource {
            request_id: queued_b.display_id().to_string(),
            session_id: None,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("promote response");

    match response {
        Response::PromoteResourceResult {
            status, snapshot, ..
        } => {
            assert_eq!(status, proto::ResourcePromoteStatus::Promoted);
            assert_eq!(snapshot.queued[0].id, queued_b.request_id());
            assert_eq!(snapshot.running[0].id, running.request_id());
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn promote_resource_request_stale_id_is_nonfatal() {
    let ctx = persistent_test_ctx();
    let mut state = MutableClientState::detached_for_test();

    let response = handle_request(
        Request::PromoteResource {
            request_id: "rs-9999".to_string(),
            session_id: None,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("promote response");

    match response {
        Response::PromoteResourceResult {
            status, message, ..
        } => {
            assert_eq!(status, proto::ResourcePromoteStatus::NotFound);
            assert!(message.contains("no longer queued"));
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn boot_housekeeping_succeeds_with_empty_task_delegation_tables() {
    let db = Db::open_in_memory().expect("in-memory db");
    run_boot_housekeeping(&db);
    assert_eq!(db.reconcile_orphaned_task_delegations().unwrap(), 0);
}

#[tokio::test]
#[expect(
    deprecated,
    reason = "db-async-foundation bridge; migrated later in db-async-session-log"
)]
async fn retention_tick_runs_one_pass_without_sleep() {
    let db = Db::open_in_memory().expect("in-memory db");
    let session = db.create_session("p", "/x", "Build").unwrap();
    db.write_blocking(move |conn| {
        conn.execute(
            "UPDATE sessions SET ended_at = 10, last_active_at = 10 WHERE session_id = ?1",
            [session.session_id.to_string()],
        )?;
        conn.execute(
            "INSERT INTO session_events (session_id, ts_ms, type, data_json)
                 VALUES (?1, 10000, 'user_message', '{}')",
            [session.session_id.to_string()],
        )?;
        Ok(())
    })
    .unwrap();
    let cfg = RetentionConfig {
        payload_window_days: 1,
        vacuum_interval_days: 0,
        ..RetentionConfig::default()
    };

    run_retention_tick_db(db.clone(), cfg).await;

    let rows: i64 = db
        .read_blocking(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM session_events WHERE session_id = ?1",
                [session.session_id.to_string()],
                |row| row.get(0),
            )
            .context("counting session_events")
        })
        .unwrap();
    assert_eq!(rows, 0);
}

fn attached_state(
    ctx: &Arc<DaemonContext>,
    project_root: &std::path::Path,
) -> (MutableClientState, Uuid) {
    let (state, session_id, _work_rx) = attached_state_with_worker_receiver(ctx, project_root);
    (state, session_id)
}

fn attached_state_with_worker_receiver(
    ctx: &Arc<DaemonContext>,
    project_root: &std::path::Path,
) -> (
    MutableClientState,
    Uuid,
    tokio::sync::mpsc::Receiver<SessionWork>,
) {
    ctx.db
        .set_workspace_trust(
            project_root,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session_row = ctx
        .db
        .create_session("p", project_root.to_str().unwrap(), "Build")
        .unwrap();
    let session = Arc::new(
        Session::resume(ctx.db.clone(), session_row.session_id)
            .unwrap()
            .unwrap(),
    );
    let locks = Arc::new(LockManager::from_db(ctx.db.clone()).expect("locks"));
    let (handle, work_rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
    (
        MutableClientState {
            principal: ClientPrincipal::owner(),
            attached: Some(AttachedSession {
                handle,
                _interactive_guard: None,
            }),
            pending_replay: Vec::new(),
            pending_uploads: HashMap::new(),
            ready_attachments: HashMap::new(),
            upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
            upload_limits: AttachmentUploadLimits::default(),
            terminal_views: HashSet::new(),
            terminal_host: test_terminal_host(),
        },
        session_row.session_id,
        work_rx,
    )
}

#[test]
fn client_state_split_snapshot_republishes_on_attach_and_detach() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, session_id) = attached_state(&ctx, tmp.path());

    let attached = state.shared_snapshot();
    assert_eq!(
        attached
            .attached
            .as_ref()
            .map(SharedAttachedSession::session_id),
        Some(session_id)
    );

    state.attached = None;
    let detached = state.shared_snapshot();
    assert!(detached.attached.is_none());
}

#[test]
fn client_state_split_handler_holding_a_stale_snapshot_still_scrubs() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    state.principal = remote_principal();
    let table = table_for("stale-secret");
    let mut stale = (*state.shared_snapshot()).clone();
    stale.attached = Some(SharedAttachedSession {
        session_id: state.attached.as_ref().unwrap().handle.session_id,
        project_root: state.attached.as_ref().unwrap().handle.project_root.clone(),
        redaction_table: table,
        active_tool_names: state.attached.as_ref().unwrap().handle.active_tool_names(),
    });
    state.attached = None;

    let response = proto::Response::SessionMessages {
        session_id: Uuid::new_v4(),
        messages: vec![proto::SessionMessage {
            seq: 1,
            ts_ms: 1,
            role: proto::MessageRole::Agent,
            text: "stale-secret remains protected".to_string(),
        }],
        has_more: false,
    };
    let redact = stale
        .attached
        .as_ref()
        .expect("stale snapshot remains attached")
        .redaction_table();
    let scrubbed = scrub_proto_response(response, &redact).expect("response scrubs");
    let rendered = serde_json::to_string(&scrubbed).unwrap();
    assert!(!rendered.contains("stale-secret"), "{rendered}");
}

#[tokio::test]
async fn client_state_split_concurrent_entry_point_authorizes_before_work() {
    let ctx = test_ctx();
    let state = MutableClientState::detached_with_principal(
        ctx.upload_accounting.clone(),
        remote_principal(),
        ctx.terminal_host.clone(),
    );
    let shared = state.shared_snapshot();
    let request = Request::FsRead {
        project_root: "/not-granted".to_string(),
        path: "README.md".to_string(),
        base64: false,
    };

    let err = handle_concurrent_request(request, shared, ctx)
        .await
        .expect_err("unauthorized request should fail before handler work");
    assert_eq!(err.code, ErrorCode::Authorization);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchMatrixClass {
    Readonly,
    Mutating,
    AccessControlled,
}

#[derive(Debug, Clone, Copy)]
struct DispatchMatrixRow {
    kind: &'static str,
    class: DispatchMatrixClass,
    authz: &'static str,
}

macro_rules! dispatch_matrix_rows_from_command_table {
        (($($context:ident),*) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
            vec![$(
                DispatchMatrixRow {
                    kind: $kind,
                    class: dispatch_matrix_class_for_command($kind, stringify!($authz), $mutating),
                    authz: stringify!($authz),
                },
            )+]
        }};
    }

/// Shared daemon-dispatch matrix declaration. Successor prompts extend
/// this same table's coverage cases for mutating and authz-specific
/// requests instead of creating a second request-kind list.
fn dispatch_matrix_rows() -> Vec<DispatchMatrixRow> {
    proto::command!(dispatch_matrix_rows_from_command_table)
}

fn dispatch_matrix_class_for_command(
    kind: &'static str,
    authz: &'static str,
    mutating: bool,
) -> DispatchMatrixClass {
    match (kind, authz, mutating) {
        ("fs_list", "project_files", false)
        | ("fs_stat", "project_files", false)
        | ("fs_read", "project_files", false)
        | ("git_status", "project_files", false)
        | ("git_diff_file", "project_files", false)
        | ("list_sessions", "public_read", false)
        | ("read_session_messages", "custom", false)
        | ("read_history_page", "custom", false)
        | ("session_live_status", "public_read", false)
        | ("goal_status", "session_row_reader", false)
        | ("list_skills", "project_read", false)
        | ("daemon_status", "public_read", false)
        | ("guidance_estimate", "project_read", false) => DispatchMatrixClass::Readonly,
        ("attach_terminal", "terminal", false)
        | ("terminal_input", "terminal", false)
        | ("terminal_resize", "terminal", false)
        | ("subagent_transcript", "custom", false)
        | ("resource_snapshot", "owner_only", false)
        | ("list_scheduled_jobs", "owner_only", false)
        | ("list_agents", "owner_only", false)
        | ("list_models", "owner_only", false)
        | ("list_assistants", "owner_only", false)
        | ("export_session_data", "owner_only", false)
        | ("get_usage_counts", "owner_only", false)
        | ("stats_rollup", "owner_only", false) => DispatchMatrixClass::AccessControlled,
        (_, _, true) => DispatchMatrixClass::Mutating,
        other => panic!("dispatch matrix request kind is unclassified: {other:?}"),
    }
}

#[derive(Debug, Clone, Copy)]
struct ReadonlyDispatchCase {
    kind: &'static str,
    case: ReadonlyDispatchCaseKind,
}

#[derive(Debug, Clone, Copy)]
enum ReadonlyDispatchCaseKind {
    FsList,
    FsStat,
    FsRead,
    GitStatus,
    GitDiffFile,
    ListSessions,
    ReadSessionMessages,
    ReadHistoryPage,
    SessionLiveStatus,
    GoalStatus,
    ListSkills,
    DaemonStatus,
    GuidanceEstimate,
}

fn readonly_dispatch_happy_cases() -> Vec<ReadonlyDispatchCase> {
    readonly_dispatch_case_list()
}

fn readonly_dispatch_malformed_cases() -> Vec<ReadonlyDispatchCase> {
    readonly_dispatch_case_list()
}

fn readonly_dispatch_case_list() -> Vec<ReadonlyDispatchCase> {
    vec![
        ReadonlyDispatchCase {
            kind: "fs_list",
            case: ReadonlyDispatchCaseKind::FsList,
        },
        ReadonlyDispatchCase {
            kind: "fs_stat",
            case: ReadonlyDispatchCaseKind::FsStat,
        },
        ReadonlyDispatchCase {
            kind: "fs_read",
            case: ReadonlyDispatchCaseKind::FsRead,
        },
        ReadonlyDispatchCase {
            kind: "git_status",
            case: ReadonlyDispatchCaseKind::GitStatus,
        },
        ReadonlyDispatchCase {
            kind: "git_diff_file",
            case: ReadonlyDispatchCaseKind::GitDiffFile,
        },
        ReadonlyDispatchCase {
            kind: "list_sessions",
            case: ReadonlyDispatchCaseKind::ListSessions,
        },
        ReadonlyDispatchCase {
            kind: "read_session_messages",
            case: ReadonlyDispatchCaseKind::ReadSessionMessages,
        },
        ReadonlyDispatchCase {
            kind: "read_history_page",
            case: ReadonlyDispatchCaseKind::ReadHistoryPage,
        },
        ReadonlyDispatchCase {
            kind: "session_live_status",
            case: ReadonlyDispatchCaseKind::SessionLiveStatus,
        },
        ReadonlyDispatchCase {
            kind: "goal_status",
            case: ReadonlyDispatchCaseKind::GoalStatus,
        },
        ReadonlyDispatchCase {
            kind: "list_skills",
            case: ReadonlyDispatchCaseKind::ListSkills,
        },
        ReadonlyDispatchCase {
            kind: "daemon_status",
            case: ReadonlyDispatchCaseKind::DaemonStatus,
        },
        ReadonlyDispatchCase {
            kind: "guidance_estimate",
            case: ReadonlyDispatchCaseKind::GuidanceEstimate,
        },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchEffectClass {
    Durable,
    InMemory,
    DriverForwarded,
}

#[derive(Debug, Clone, Copy)]
struct MutatingDispatchCase {
    kind: &'static str,
    effect_class: DispatchEffectClass,
    observation: &'static str,
}

fn mutating_dispatch_happy_cases() -> Vec<MutatingDispatchCase> {
    mutating_dispatch_case_list()
}

fn mutating_dispatch_malformed_cases() -> Vec<MutatingDispatchCase> {
    mutating_dispatch_case_list()
}

fn mutating_dispatch_case_list() -> Vec<MutatingDispatchCase> {
    use DispatchEffectClass::{DriverForwarded, Durable, InMemory};
    vec![
        MutatingDispatchCase {
            kind: "attach",
            effect_class: Durable,
            observation: "attached response plus live session registration",
        },
        MutatingDispatchCase {
            kind: "send_user_message",
            effect_class: DriverForwarded,
            observation: "SessionWork::UserMessage delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "steer_delegation",
            effect_class: DriverForwarded,
            observation: "SessionWork::SteerDelegation delivered to live target worker",
        },
        MutatingDispatchCase {
            kind: "begin_attachment_upload",
            effect_class: InMemory,
            observation: "upload id accepted by later chunk request on same connection",
        },
        MutatingDispatchCase {
            kind: "upload_attachment_chunk",
            effect_class: InMemory,
            observation: "chunk advances upload so finish succeeds",
        },
        MutatingDispatchCase {
            kind: "finish_attachment_upload",
            effect_class: InMemory,
            observation: "ready image ref can be consumed by a later user message request",
        },
        MutatingDispatchCase {
            kind: "cancel_attachment_upload",
            effect_class: InMemory,
            observation: "cancelled upload id cannot be finished",
        },
        MutatingDispatchCase {
            kind: "remove_queued_user_message",
            effect_class: DriverForwarded,
            observation: "SessionWork::RemoveQueuedUserMessage delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "remove_newest_queued_user_message",
            effect_class: DriverForwarded,
            observation: "SessionWork::RemoveNewestQueuedUserMessage delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "remove_editable_queued_user_messages",
            effect_class: DriverForwarded,
            observation: "SessionWork::RemoveEditableQueuedUserMessages delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "resume_paused_work",
            effect_class: Durable,
            observation: "paused_session_work status becomes resumed",
        },
        MutatingDispatchCase {
            kind: "cancel_paused_work",
            effect_class: Durable,
            observation: "paused_session_work status becomes cancelled",
        },
        MutatingDispatchCase {
            kind: "repair_resume",
            effect_class: DriverForwarded,
            observation: "SessionWork::RepairResume delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_goal_status",
            effect_class: Durable,
            observation: "session goal status changes",
        },
        MutatingDispatchCase {
            kind: "clear_goal",
            effect_class: Durable,
            observation: "session goal is closed",
        },
        MutatingDispatchCase {
            kind: "create_assistant_session",
            effect_class: Durable,
            observation: "deferred assistant session worker is registered",
        },
        MutatingDispatchCase {
            kind: "auto_title",
            effect_class: Durable,
            observation: "untitled session row receives generated title",
        },
        MutatingDispatchCase {
            kind: "curator",
            effect_class: Durable,
            observation: "skill curator state changes through daemon-owned DB/filesystem path",
        },
        MutatingDispatchCase {
            kind: "cancel_turn",
            effect_class: DriverForwarded,
            observation: "SessionWork::Cancel delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "fs_write",
            effect_class: Durable,
            observation: "file contents written under project root",
        },
        MutatingDispatchCase {
            kind: "fs_create_dir",
            effect_class: Durable,
            observation: "directory created under project root",
        },
        MutatingDispatchCase {
            kind: "fs_rename",
            effect_class: Durable,
            observation: "file moves from source path to destination path",
        },
        MutatingDispatchCase {
            kind: "fs_delete",
            effect_class: Durable,
            observation: "file removed under project root",
        },
        MutatingDispatchCase {
            kind: "open_terminal",
            effect_class: InMemory,
            observation: "terminal id can be closed on same connection",
        },
        MutatingDispatchCase {
            kind: "close_terminal",
            effect_class: InMemory,
            observation: "closed terminal rejects later attachment",
        },
        MutatingDispatchCase {
            kind: "lsp_control",
            effect_class: InMemory,
            observation: "typed result and notice event emitted for attached session",
        },
        MutatingDispatchCase {
            kind: "resolve_interrupt",
            effect_class: DriverForwarded,
            observation: "SessionWork::ResolveInterrupt delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "archive_session",
            effect_class: Durable,
            observation: "session archived_at becomes set",
        },
        MutatingDispatchCase {
            kind: "unarchive_session",
            effect_class: Durable,
            observation: "session archived_at is cleared",
        },
        MutatingDispatchCase {
            kind: "fork_session",
            effect_class: Durable,
            observation: "fork session row references parent session",
        },
        MutatingDispatchCase {
            kind: "discard_session",
            effect_class: Durable,
            observation: "ephemeral session row is deleted",
        },
        MutatingDispatchCase {
            kind: "btw_create",
            effect_class: Durable,
            observation: "hidden persistent btw fork row references parent session",
        },
        MutatingDispatchCase {
            kind: "btw_end",
            effect_class: Durable,
            observation: "hidden persistent btw fork row is deleted",
        },
        MutatingDispatchCase {
            kind: "rename_session",
            effect_class: Durable,
            observation: "session title is updated",
        },
        MutatingDispatchCase {
            kind: "share_session",
            effect_class: Durable,
            observation: "shared_with_collaborators flag changes",
        },
        MutatingDispatchCase {
            kind: "record_session_note",
            effect_class: Durable,
            observation: "user_note session event is persisted",
        },
        MutatingDispatchCase {
            kind: "delete_session",
            effect_class: Durable,
            observation: "session row is deleted",
        },
        MutatingDispatchCase {
            kind: "promote_resource",
            effect_class: InMemory,
            observation: "queued resource request status changes to promoted response",
        },
        MutatingDispatchCase {
            kind: "create_scheduled_job",
            effect_class: Durable,
            observation: "scheduled job row is persisted in the shared daemon",
        },
        MutatingDispatchCase {
            kind: "delete_scheduled_job",
            effect_class: Durable,
            observation: "scheduled job row is deleted in the shared daemon",
        },
        MutatingDispatchCase {
            kind: "set_scheduled_job_enabled",
            effect_class: Durable,
            observation: "scheduled job enabled state changes in the shared daemon",
        },
        MutatingDispatchCase {
            kind: "run_scheduled_job",
            effect_class: Durable,
            observation: "scheduled job run result is recorded in the shared daemon",
        },
        MutatingDispatchCase {
            kind: "set_active_model",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetActiveModel delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_agent",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetAgent delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_llm_mode",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetLlmMode delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_session_llm_mode",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetSessionLlmMode delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_approval_mode",
            effect_class: InMemory,
            observation: "approval mode response and broadcast event reflect new mode",
        },
        MutatingDispatchCase {
            kind: "set_delegation_recursion",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetDelegationRecursion delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_sandbox",
            effect_class: InMemory,
            observation: "sandbox state response and broadcast event reflect new mode",
        },
        MutatingDispatchCase {
            kind: "set_sandbox_escalation",
            effect_class: InMemory,
            observation: "sandbox escalation response and broadcast event reflect new state",
        },
        MutatingDispatchCase {
            kind: "set_preflight",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetPreflight delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_trusted_only",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetTrustedOnly delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_redaction",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetRedaction delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_tandem_models",
            effect_class: DriverForwarded,
            observation: "SessionWork::SetTandemModels delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "set_caffeinate",
            effect_class: InMemory,
            observation: "caffeinate response plus global state event",
        },
        MutatingDispatchCase {
            kind: "cancel_schedule",
            effect_class: DriverForwarded,
            observation: "SessionWork::CancelSchedule delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "prune",
            effect_class: DriverForwarded,
            observation: "SessionWork::Prune delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "compact",
            effect_class: DriverForwarded,
            observation: "SessionWork::Compact delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "pin",
            effect_class: DriverForwarded,
            observation: "SessionWork::Pin delivered to attached worker",
        },
        MutatingDispatchCase {
            kind: "store_flycockpit_credential",
            effect_class: Durable,
            observation: "credential file is written",
        },
        MutatingDispatchCase {
            kind: "clear_flycockpit_credential",
            effect_class: Durable,
            observation: "credential store no longer loads a credential",
        },
        MutatingDispatchCase {
            kind: "refresh_env",
            effect_class: InMemory,
            observation: "attached worker env overlay changes",
        },
        MutatingDispatchCase {
            kind: "refresh_config",
            effect_class: InMemory,
            observation: "attached worker config snapshot generation changes",
        },
        MutatingDispatchCase {
            kind: "record_usage",
            effect_class: Durable,
            observation: "usage count appears in subsequent usage_counts query",
        },
        MutatingDispatchCase {
            kind: "stop_daemon",
            effect_class: InMemory,
            observation: "shutdown context enters draining phase",
        },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthzExpectation {
    Allow(AuthzAllowedOutcome),
    Deny(ErrorCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthzAllowedOutcome {
    Response,
    Error(ErrorCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthzLevel {
    Owner,
    Writer,
    Readonly,
    NoAccess,
}

impl AuthzLevel {
    const ALL: [Self; 4] = [Self::Owner, Self::Writer, Self::Readonly, Self::NoAccess];

    fn label(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Writer => "writer",
            Self::Readonly => "readonly",
            Self::NoAccess => "no_access",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AuthzDispatchCase {
    kind: &'static str,
    owner: AuthzExpectation,
    writer: AuthzExpectation,
    readonly: AuthzExpectation,
    no_access: AuthzExpectation,
    known_holes: &'static [AuthzKnownHole],
}

#[derive(Debug, Clone, Copy)]
struct AuthzKnownHole {
    marker: &'static str,
    level: AuthzLevel,
    expected: ErrorCode,
    actual: AuthzAllowedOutcome,
}

impl AuthzDispatchCase {
    fn expectation(self, level: AuthzLevel) -> AuthzExpectation {
        match level {
            AuthzLevel::Owner => self.owner,
            AuthzLevel::Writer => self.writer,
            AuthzLevel::Readonly => self.readonly,
            AuthzLevel::NoAccess => self.no_access,
        }
    }
}

fn authz_owner_only(kind: &'static str) -> AuthzDispatchCase {
    AuthzDispatchCase {
        kind,
        owner: authz_allow(kind),
        writer: AuthzExpectation::Deny(ErrorCode::Authorization),
        readonly: AuthzExpectation::Deny(ErrorCode::Authorization),
        no_access: AuthzExpectation::Deny(ErrorCode::Authorization),
        known_holes: &[],
    }
}

fn authz_session_writer(kind: &'static str) -> AuthzDispatchCase {
    authz_session_writer_with_known_holes(kind, &[])
}

fn authz_session_writer_with_known_holes(
    kind: &'static str,
    known_holes: &'static [AuthzKnownHole],
) -> AuthzDispatchCase {
    AuthzDispatchCase {
        kind,
        owner: authz_allow(kind),
        writer: authz_allow(kind),
        readonly: AuthzExpectation::Deny(ErrorCode::ReadOnly),
        no_access: AuthzExpectation::Deny(ErrorCode::Authorization),
        known_holes,
    }
}

fn authz_session_reader(kind: &'static str) -> AuthzDispatchCase {
    AuthzDispatchCase {
        kind,
        owner: authz_allow(kind),
        writer: authz_allow(kind),
        readonly: authz_allow(kind),
        no_access: AuthzExpectation::Deny(ErrorCode::Authorization),
        known_holes: &[],
    }
}

fn authz_project_files(kind: &'static str) -> AuthzDispatchCase {
    AuthzDispatchCase {
        kind,
        owner: authz_allow(kind),
        writer: authz_allow(kind),
        readonly: AuthzExpectation::Deny(ErrorCode::Authorization),
        no_access: AuthzExpectation::Deny(ErrorCode::Authorization),
        known_holes: &[],
    }
}

fn authz_project_read(kind: &'static str) -> AuthzDispatchCase {
    AuthzDispatchCase {
        kind,
        owner: authz_allow(kind),
        writer: authz_allow(kind),
        readonly: authz_allow(kind),
        no_access: AuthzExpectation::Deny(ErrorCode::Authorization),
        known_holes: &[],
    }
}

fn authz_terminal(kind: &'static str) -> AuthzDispatchCase {
    AuthzDispatchCase {
        kind,
        owner: authz_allow(kind),
        writer: authz_allow(kind),
        readonly: AuthzExpectation::Deny(ErrorCode::Authorization),
        no_access: AuthzExpectation::Deny(ErrorCode::Authorization),
        known_holes: &[],
    }
}

fn authz_allow(kind: &'static str) -> AuthzExpectation {
    AuthzExpectation::Allow(authz_allowed_outcome(kind))
}

fn authz_allowed_outcome(kind: &str) -> AuthzAllowedOutcome {
    match kind {
        "attach"
        | "subagent_transcript"
        | "cancel_attachment_upload"
        | "goal_status"
        | "clear_goal"
        | "list_assistants"
        | "export_session_data"
        | "curator"
        | "resume_paused_work"
        | "cancel_paused_work"
        | "fs_list"
        | "fs_write"
        | "fs_create_dir"
        | "lsp_control"
        | "read_session_messages"
        | "read_history_page"
        | "unarchive_session"
        | "fork_session"
        | "btw_create"
        | "btw_end"
        | "rename_session"
        | "share_session"
        | "record_session_note"
        | "list_skills"
        | "resource_snapshot"
        | "promote_resource"
        | "set_approval_mode"
        | "set_sandbox"
        | "set_sandbox_escalation"
        | "set_caffeinate"
        | "refresh_env"
        | "record_usage"
        | "get_usage_counts"
        | "stats_rollup"
        | "guidance_estimate"
        | "stop_daemon" => AuthzAllowedOutcome::Response,
        "begin_attachment_upload"
        | "upload_attachment_chunk"
        | "finish_attachment_upload"
        | "fs_stat"
        | "fs_read"
        | "fs_rename"
        | "fs_delete"
        | "git_status"
        | "git_diff_file"
        | "attach_terminal"
        | "terminal_input"
        | "terminal_resize"
        | "close_terminal"
        | "create_scheduled_job"
        | "list_scheduled_jobs"
        | "delete_scheduled_job"
        | "set_scheduled_job_enabled"
        | "run_scheduled_job"
        | "auto_title"
        | "create_assistant_session"
        | "store_flycockpit_credential"
        | "clear_flycockpit_credential"
        | "set_goal_status" => AuthzAllowedOutcome::Error(ErrorCode::BadRequest),
        "open_terminal" => AuthzAllowedOutcome::Error(ErrorCode::RootMissing),
        "list_agents" | "list_models" => AuthzAllowedOutcome::Error(ErrorCode::NotAttached),
        "send_user_message"
        | "steer_delegation"
        | "remove_queued_user_message"
        | "remove_newest_queued_user_message"
        | "remove_editable_queued_user_messages"
        | "repair_resume"
        | "cancel_turn"
        | "resolve_interrupt"
        | "archive_session"
        | "discard_session"
        | "delete_session"
        | "set_active_model"
        | "set_agent"
        | "set_llm_mode"
        | "set_session_llm_mode"
        | "set_delegation_recursion"
        | "set_preflight"
        | "set_trusted_only"
        | "set_redaction"
        | "set_tandem_models"
        | "refresh_config"
        | "cancel_schedule"
        | "prune"
        | "compact"
        | "pin" => AuthzAllowedOutcome::Error(ErrorCode::Internal),
        other => panic!("unhandled authz allowed outcome for {other}"),
    }
}

fn authz_dispatch_cases() -> Vec<AuthzDispatchCase> {
    vec![
        authz_session_reader("attach"),
        authz_session_reader("subagent_transcript"),
        authz_session_writer("send_user_message"),
        authz_session_writer("steer_delegation"),
        authz_session_writer("begin_attachment_upload"),
        authz_session_writer("upload_attachment_chunk"),
        authz_session_writer("finish_attachment_upload"),
        authz_session_writer("cancel_attachment_upload"),
        authz_session_writer("remove_queued_user_message"),
        authz_session_writer("remove_newest_queued_user_message"),
        authz_session_writer("remove_editable_queued_user_messages"),
        authz_session_writer("resume_paused_work"),
        authz_session_writer("cancel_paused_work"),
        authz_session_writer("repair_resume"),
        authz_session_reader("goal_status"),
        authz_session_writer("set_goal_status"),
        authz_session_writer("clear_goal"),
        authz_owner_only("list_assistants"),
        authz_owner_only("create_assistant_session"),
        authz_session_writer("auto_title"),
        authz_owner_only("export_session_data"),
        authz_owner_only("curator"),
        authz_session_writer("cancel_turn"),
        authz_project_files("fs_list"),
        authz_project_files("fs_stat"),
        authz_project_files("fs_read"),
        authz_project_files("fs_write"),
        authz_project_files("fs_create_dir"),
        authz_project_files("fs_rename"),
        authz_owner_only("fs_delete"),
        authz_project_files("git_status"),
        authz_project_files("git_diff_file"),
        authz_terminal("open_terminal"),
        authz_terminal("attach_terminal"),
        authz_terminal("terminal_input"),
        authz_terminal("terminal_resize"),
        authz_terminal("close_terminal"),
        authz_terminal("lsp_control"),
        authz_session_writer("resolve_interrupt"),
        authz_session_reader("read_session_messages"),
        authz_session_reader("read_history_page"),
        authz_session_writer("archive_session"),
        authz_session_writer("unarchive_session"),
        authz_session_writer("fork_session"),
        authz_session_writer("discard_session"),
        authz_session_writer("btw_create"),
        authz_session_writer("btw_end"),
        authz_session_writer("rename_session"),
        authz_owner_only("share_session"),
        authz_session_writer("record_session_note"),
        authz_session_writer("delete_session"),
        authz_project_read("list_skills"),
        authz_owner_only("resource_snapshot"),
        authz_owner_only("promote_resource"),
        authz_owner_only("create_scheduled_job"),
        authz_owner_only("list_scheduled_jobs"),
        authz_owner_only("delete_scheduled_job"),
        authz_owner_only("set_scheduled_job_enabled"),
        authz_owner_only("run_scheduled_job"),
        authz_owner_only("list_agents"),
        authz_owner_only("list_models"),
        authz_session_writer("set_active_model"),
        authz_session_writer("set_agent"),
        authz_session_writer("set_llm_mode"),
        authz_session_writer("set_session_llm_mode"),
        authz_session_writer("set_approval_mode"),
        authz_session_writer("set_delegation_recursion"),
        authz_session_writer("set_sandbox"),
        authz_session_writer("set_sandbox_escalation"),
        authz_session_writer("set_preflight"),
        authz_session_writer("set_trusted_only"),
        authz_session_writer("set_redaction"),
        authz_session_writer("set_tandem_models"),
        authz_owner_only("set_caffeinate"),
        authz_session_writer("cancel_schedule"),
        authz_session_writer("prune"),
        authz_session_writer("compact"),
        authz_session_writer("pin"),
        authz_owner_only("store_flycockpit_credential"),
        authz_owner_only("clear_flycockpit_credential"),
        authz_session_writer("refresh_env"),
        authz_session_writer("refresh_config"),
        authz_owner_only("record_usage"),
        authz_owner_only("get_usage_counts"),
        authz_owner_only("stats_rollup"),
        authz_project_read("guidance_estimate"),
        authz_owner_only("stop_daemon"),
    ]
}

#[cfg(unix)]
async fn dispatch_matrix_request(
    ctx: &Arc<DaemonContext>,
    request: Request,
) -> std::result::Result<Response, ErrorPayload> {
    dispatch_matrix_request_after(ctx, Vec::new(), request).await
}

#[cfg(unix)]
async fn dispatch_matrix_request_after(
    ctx: &Arc<DaemonContext>,
    prelude: Vec<Request>,
    request: Request,
) -> std::result::Result<Response, ErrorPayload> {
    let result = dispatch_authz_request_after(
        ctx,
        ClientPrincipal::owner(),
        prelude.clone(),
        None,
        None,
        request.clone(),
    )
    .await;
    if matches!(
        &result,
        Err(ErrorPayload {
            code: ErrorCode::Internal,
            message,
        }) if message == "daemon connection closed"
    ) {
        return dispatch_authz_request_after(
            ctx,
            ClientPrincipal::owner(),
            prelude,
            None,
            None,
            request,
        )
        .await;
    }
    result
}

#[cfg(unix)]
async fn dispatch_authz_request_after(
    ctx: &Arc<DaemonContext>,
    principal: ClientPrincipal,
    prelude: Vec<Request>,
    unshare_session_after_prelude: Option<Uuid>,
    worker_rx_to_drop_after_prelude: Option<tokio::sync::mpsc::Receiver<SessionWork>>,
    request: Request,
) -> std::result::Result<Response, ErrorPayload> {
    let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
    let mut client = ProtoStream::new(client_stream);
    let server = tokio::spawn(handle_client_transport_as(
        server_stream,
        ctx.clone(),
        principal,
    ));
    match recv_body(&mut client).await {
        Body::Response { id, response } => {
            assert_eq!(id, Uuid::nil());
            assert!(matches!(*response, Response::DaemonStatus { .. }));
        }
        other => panic!("expected daemon hello, got {other:?}"),
    }

    for prelude_request in prelude {
        let prelude_id = Uuid::new_v4();
        client
            .send(&Envelope::request(prelude_id, prelude_request))
            .await
            .expect("send prelude request");
        recv_dispatch_matrix_response(&mut client, prelude_id)
            .await
            .expect("prelude request succeeds");
    }

    drop(worker_rx_to_drop_after_prelude);

    if let Some(session_id) = unshare_session_after_prelude {
        ctx.db
            .set_session_shared_with_collaborators(session_id, false)
            .expect("revoke shared session before authz matrix request");
    }

    let id = Uuid::new_v4();
    client
        .send(&Envelope::request(id, request))
        .await
        .expect("send dispatch request");
    let result = recv_dispatch_matrix_response(&mut client, id).await;
    drop(client);
    server
        .await
        .expect("server task joins")
        .expect("server task succeeds");
    result
}

#[cfg(unix)]
async fn dispatch_matrix_request_after_collect_events(
    ctx: &Arc<DaemonContext>,
    prelude: Vec<Request>,
    request: Request,
) -> (
    std::result::Result<Response, ErrorPayload>,
    Vec<proto::Event>,
) {
    let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
    let mut client = ProtoStream::new(client_stream);
    let server = tokio::spawn(handle_client_transport(server_stream, ctx.clone()));
    match recv_body(&mut client).await {
        Body::Response { id, response } => {
            assert_eq!(id, Uuid::nil());
            assert!(matches!(*response, Response::DaemonStatus { .. }));
        }
        other => panic!("expected daemon hello, got {other:?}"),
    }

    for prelude_request in prelude {
        let prelude_id = Uuid::new_v4();
        client
            .send(&Envelope::request(prelude_id, prelude_request))
            .await
            .expect("send prelude request");
        recv_dispatch_matrix_response(&mut client, prelude_id)
            .await
            .expect("prelude request succeeds");
    }

    let id = Uuid::new_v4();
    client
        .send(&Envelope::request(id, request))
        .await
        .expect("send dispatch request");

    let mut events = Vec::new();
    let result = loop {
        match recv_body(&mut client).await {
            Body::Response { id: got, response } => {
                assert_eq!(got, id);
                break Ok(*response);
            }
            Body::Error {
                id: Some(got),
                error,
            } => {
                assert_eq!(got, id);
                break Err(error);
            }
            Body::Event { event } => events.push(event),
            other => panic!("expected dispatch response/error/event, got {other:?}"),
        }
    };

    while let Ok(body) =
        tokio::time::timeout(std::time::Duration::from_millis(50), recv_body(&mut client)).await
    {
        match body {
            Body::Event { event } => events.push(event),
            other => panic!("unexpected post-response dispatch body: {other:?}"),
        }
    }

    drop(client);
    server
        .await
        .expect("server task joins")
        .expect("server task succeeds");
    (result, events)
}

#[cfg(unix)]
async fn dispatch_matrix_raw_line(
    ctx: &Arc<DaemonContext>,
    request_id: Uuid,
    line: String,
) -> std::result::Result<Response, ErrorPayload> {
    let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
    let mut client = ProtoStream::new(client_stream);
    let server = tokio::spawn(handle_client_transport(server_stream, ctx.clone()));
    match recv_body(&mut client).await {
        Body::Response { id, response } => {
            assert_eq!(id, Uuid::nil());
            assert!(matches!(*response, Response::DaemonStatus { .. }));
        }
        other => panic!("expected daemon hello, got {other:?}"),
    }
    client
        .send_raw_line(line)
        .await
        .expect("send raw dispatch request");
    let result = recv_dispatch_matrix_response(&mut client, request_id).await;
    drop(client);
    server
        .await
        .expect("server task joins")
        .expect("server task succeeds");
    result
}

#[cfg(unix)]
async fn recv_dispatch_matrix_response<S>(
    proto: &mut ProtoStream<S>,
    request_id: Uuid,
) -> std::result::Result<Response, ErrorPayload>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        match recv_body_result(proto).await? {
            Body::Response { id, response } => {
                assert_eq!(id, request_id);
                return Ok(*response);
            }
            Body::Error { id, error } => {
                assert_eq!(id, Some(request_id));
                return Err(error);
            }
            Body::Event { .. } => continue,
            other => panic!("expected dispatch response/error, got {other:?}"),
        }
    }
}

async fn recv_body_result<S>(proto: &mut ProtoStream<S>) -> std::result::Result<Body, ErrorPayload>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match proto.recv().await {
        Ok(Some(RecvFrame::Envelope(env))) => Ok(env.body),
        Ok(Some(RecvFrame::VersionMismatch { v, .. })) => Err(ErrorPayload {
            code: ErrorCode::ProtocolVersion,
            message: proto::version_mismatch_message(v),
        }),
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::Internal,
            message: "daemon connection closed".to_string(),
        }),
        Err(error) => Err(ErrorPayload {
            code: ErrorCode::Internal,
            message: format!("daemon read failed: {error}"),
        }),
    }
}

fn assert_dispatch_matrix_coverage_complete() {
    let readonly: BTreeSet<_> = dispatch_matrix_rows()
        .into_iter()
        .filter(|row| row.class == DispatchMatrixClass::Readonly)
        .map(|row| row.kind)
        .collect();
    let mutating: BTreeSet<_> = dispatch_matrix_rows()
        .into_iter()
        .filter(|row| row.class == DispatchMatrixClass::Mutating)
        .map(|row| row.kind)
        .collect();
    let controlled: BTreeSet<_> = dispatch_matrix_rows()
        .into_iter()
        .filter(|row| row.authz != "public_read")
        .map(|row| row.kind)
        .collect();
    let happy: BTreeSet<_> = readonly_dispatch_happy_cases()
        .into_iter()
        .map(|case| case.kind)
        .collect();
    let malformed: BTreeSet<_> = readonly_dispatch_malformed_cases()
        .into_iter()
        .map(|case| case.kind)
        .collect();
    let mutating_happy: BTreeSet<_> = mutating_dispatch_happy_cases()
        .into_iter()
        .map(|case| {
            assert!(
                !case.observation.is_empty(),
                "{} needs an observation channel",
                case.kind
            );
            case.kind
        })
        .collect();
    let mutating_malformed: BTreeSet<_> = mutating_dispatch_malformed_cases()
        .into_iter()
        .map(|case| case.kind)
        .collect();
    let authz_declared: BTreeSet<_> = authz_dispatch_cases()
        .into_iter()
        .map(|case| case.kind)
        .collect();

    assert_eq!(
        readonly, happy,
        "every readonly dispatch kind needs a happy socket case"
    );
    assert_eq!(
        readonly, malformed,
        "every readonly dispatch kind needs a malformed/invalid-state socket case"
    );
    assert_eq!(
        mutating, mutating_happy,
        "every mutating dispatch kind needs a happy socket case"
    );
    assert_eq!(
        mutating, mutating_malformed,
        "every mutating dispatch kind needs a malformed/invalid-state socket case"
    );
    assert_eq!(
        controlled, authz_declared,
        "every non-public dispatch kind needs an authz matrix declaration"
    );
    assert!(
        readonly.len() >= 10 && mutating.len() >= 40 && authz_declared.len() >= 60,
        "dispatch_matrix coverage must be non-vacuous"
    );
}

#[test]
fn dispatch_matrix_readonly_coverage_is_complete() {
    assert_dispatch_matrix_coverage_complete();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_matrix_readonly_cases_traverse_socket_path() {
    assert_dispatch_matrix_coverage_complete();
    for case in readonly_dispatch_happy_cases() {
        case.case.assert_happy_socket_case().await;
    }
    for case in readonly_dispatch_malformed_cases() {
        case.case.assert_malformed_socket_case().await;
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn dispatch_matrix_mutating_dispatch_cases_traverse_socket_path() {
    assert_dispatch_matrix_coverage_complete();
    for case in mutating_dispatch_happy_cases() {
        assert_mutating_happy_socket_case(case).await;
    }
    for case in mutating_dispatch_malformed_cases() {
        assert_mutating_malformed_socket_case(case).await;
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn authz_dispatch_matrix_covers_every_controlled_kind() {
    assert_dispatch_matrix_coverage_complete();
    for case in authz_dispatch_cases() {
        for level in AuthzLevel::ALL {
            let scenario = authz_socket_scenario(case.kind, level);
            let result = dispatch_authz_request_after(
                &scenario.ctx,
                scenario.principal,
                scenario.prelude,
                scenario.unshare_session_after_prelude,
                scenario.worker_rx_to_drop_after_prelude,
                scenario.request,
            )
            .await;
            assert_authz_matrix_result(case, level, result);
        }
        for known_hole in case.known_holes {
            assert_authz_known_hole_socket_case(case.kind, *known_hole).await;
        }
    }
}

#[cfg(unix)]
struct AuthzSocketScenario {
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    prelude: Vec<Request>,
    unshare_session_after_prelude: Option<Uuid>,
    worker_rx_to_drop_after_prelude: Option<tokio::sync::mpsc::Receiver<SessionWork>>,
    request: Request,
    target_session_id: Uuid,
    _tmp: tempfile::TempDir,
}

#[cfg(unix)]
fn assert_authz_matrix_result(
    case: AuthzDispatchCase,
    level: AuthzLevel,
    result: std::result::Result<Response, ErrorPayload>,
) {
    match case.expectation(level) {
        AuthzExpectation::Allow(expected) => {
            assert_authz_allowed_outcome(case.kind, level, expected, result);
        }
        AuthzExpectation::Deny(expected) => {
            let error = match result {
                Ok(response) => panic!(
                    "{} unexpectedly allowed {} with response {response:?}",
                    case.kind,
                    level.label()
                ),
                Err(error) => error,
            };
            assert_eq!(
                error.code,
                expected,
                "{} denied {} with wrong code: {}",
                case.kind,
                level.label(),
                error.message
            );
        }
    }
}

#[cfg(unix)]
fn assert_authz_allowed_outcome(
    kind: &str,
    level: AuthzLevel,
    expected: AuthzAllowedOutcome,
    result: std::result::Result<Response, ErrorPayload>,
) {
    match (expected, result) {
        (AuthzAllowedOutcome::Response, Ok(_)) => {}
        (AuthzAllowedOutcome::Response, Err(error)) => panic!(
            "{kind} unexpectedly failed allowed {} cell with {:?}: {}",
            level.label(),
            error.code,
            error.message
        ),
        (AuthzAllowedOutcome::Error(expected), Err(error)) => assert_eq!(
            error.code,
            expected,
            "{kind} allowed {} cell reached wrong post-auth error: {}",
            level.label(),
            error.message
        ),
        (AuthzAllowedOutcome::Error(expected), Ok(response)) => panic!(
            "{kind} allowed {} cell expected post-auth {expected:?}, got response {response:?}",
            level.label()
        ),
    }
}

#[cfg(unix)]
async fn assert_authz_known_hole_socket_case(kind: &'static str, known_hole: AuthzKnownHole) {
    let scenario = authz_cross_session_paused_work_scenario(kind, known_hole.level);
    let result = dispatch_authz_request_after(
        &scenario.ctx,
        scenario.principal,
        scenario.prelude,
        scenario.unshare_session_after_prelude,
        scenario.worker_rx_to_drop_after_prelude,
        scenario.request,
    )
    .await;
    match result {
        Ok(response) => {
            assert_eq!(
                known_hole.actual,
                AuthzAllowedOutcome::Response,
                "{} changed actual behavior for {} to response {response:?}",
                known_hole.marker,
                kind
            );
            assert!(matches!(response, Response::Ack), "{kind}: {response:?}");
            assert!(
                scenario
                    .ctx
                    .db
                    .paused_session_work(scenario.target_session_id)
                    .unwrap()
                    .is_none(),
                "{} did not mutate the inaccessible paused-work target for {}",
                known_hole.marker,
                kind
            );
        }
        Err(error) if error.code == known_hole.expected => panic!(
            "{} appears fixed for {}; remove the KNOWN_HOLE marker and update the matrix",
            known_hole.marker, kind
        ),
        Err(error) => panic!(
            "{} changed actual behavior for {} to {:?}: {}",
            known_hole.marker, kind, error.code, error.message
        ),
    }
}

#[cfg(unix)]
fn authz_socket_scenario(kind: &'static str, level: AuthzLevel) -> AuthzSocketScenario {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (session_id, work_rx) = live_worker_with_receiver(&ctx, tmp.path());
    ctx.db
        .set_session_shared_with_collaborators(session_id, true)
        .unwrap();
    ctx.db
        .insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "authz matrix"}),
        )
        .unwrap();

    let needs_attached = authz_kind_needs_attached_state(kind, level);
    let revokes_session_access = needs_attached && level == AuthzLevel::NoAccess;
    let principal_level = if revokes_session_access {
        AuthzLevel::Writer
    } else {
        level
    };
    let principal = authz_matrix_principal(principal_level, tmp.path(), kind);
    let prelude = if needs_attached {
        vec![attach_existing_request(session_id, tmp.path())]
    } else {
        Vec::new()
    };
    let worker_rx_to_drop_after_prelude = if needs_attached {
        Some(work_rx)
    } else {
        drop(work_rx);
        None
    };
    let unshare_session_after_prelude = revokes_session_access.then_some(session_id);

    AuthzSocketScenario {
        ctx,
        principal,
        prelude,
        unshare_session_after_prelude,
        worker_rx_to_drop_after_prelude,
        request: authz_matrix_request(kind, session_id, tmp.path()),
        target_session_id: session_id,
        _tmp: tmp,
    }
}

#[cfg(unix)]
fn authz_cross_session_paused_work_scenario(
    kind: &'static str,
    level: AuthzLevel,
) -> AuthzSocketScenario {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let accessible_root = tmp.path().join("accessible");
    let target_root = tmp.path().join("target");
    std::fs::create_dir_all(&accessible_root).unwrap();
    std::fs::create_dir_all(&target_root).unwrap();

    let (attached_session_id, work_rx) = live_worker_with_receiver(&ctx, &accessible_root);
    ctx.db
        .set_session_shared_with_collaborators(attached_session_id, true)
        .unwrap();
    let target_session = ctx
        .db
        .create_session("target", target_root.to_str().unwrap(), "Build")
        .unwrap();
    ctx.db
        .upsert_paused_session_work(
            target_session.session_id,
            "Build",
            target_root.to_str().unwrap(),
            "cross-session authz hole",
            1,
            "test-version",
        )
        .unwrap();

    AuthzSocketScenario {
        ctx,
        principal: authz_matrix_principal(level, &accessible_root, kind),
        prelude: vec![attach_existing_request(
            attached_session_id,
            &accessible_root,
        )],
        unshare_session_after_prelude: None,
        worker_rx_to_drop_after_prelude: Some(work_rx),
        request: authz_matrix_request(kind, target_session.session_id, &target_root),
        target_session_id: target_session.session_id,
        _tmp: tmp,
    }
}

#[cfg(unix)]
fn authz_matrix_principal(level: AuthzLevel, project_root: &Path, kind: &str) -> ClientPrincipal {
    let project_root = project_root.to_string_lossy().into_owned();
    match level {
        AuthzLevel::Owner => ClientPrincipal::owner(),
        AuthzLevel::Writer => {
            let grants = match kind {
                "fs_list" | "fs_stat" | "fs_read" | "fs_write" | "fs_create_dir" | "fs_rename"
                | "git_status" | "git_diff_file" => {
                    vec![principal::PrincipalGrant {
                        scope: principal::PrincipalScope::ProjectFiles,
                        project_root: Some(project_root),
                    }]
                }
                "open_terminal" | "attach_terminal" | "terminal_input" | "terminal_resize"
                | "close_terminal" => {
                    vec![principal::PrincipalGrant {
                        scope: principal::PrincipalScope::Terminal,
                        project_root: None,
                    }]
                }
                "lsp_control" => vec![
                    principal::PrincipalGrant {
                        scope: principal::PrincipalScope::Terminal,
                        project_root: None,
                    },
                    principal::PrincipalGrant {
                        scope: principal::PrincipalScope::Agent,
                        project_root: Some(project_root),
                    },
                ],
                "list_skills" | "guidance_estimate" => vec![principal::PrincipalGrant {
                    scope: principal::PrincipalScope::Agent,
                    project_root: Some(project_root),
                }],
                _ => vec![principal::PrincipalGrant {
                    scope: principal::PrincipalScope::Agent,
                    project_root: Some(project_root),
                }],
            };
            ClientPrincipal::Remote(principal::RemotePrincipal {
                user_id: "authz-writer".into(),
                grants,
            })
        }
        AuthzLevel::Readonly => ClientPrincipal::Remote(principal::RemotePrincipal {
            user_id: "authz-readonly".into(),
            grants: vec![principal::PrincipalGrant {
                scope: principal::PrincipalScope::AgentReadonly,
                project_root: Some(project_root),
            }],
        }),
        AuthzLevel::NoAccess => ClientPrincipal::Remote(principal::RemotePrincipal {
            user_id: "authz-none".into(),
            grants: Vec::new(),
        }),
    }
}

#[cfg(unix)]
fn authz_kind_needs_attached_state(kind: &str, level: AuthzLevel) -> bool {
    matches!(
        kind,
        "send_user_message"
            | "begin_attachment_upload"
            | "upload_attachment_chunk"
            | "finish_attachment_upload"
            | "cancel_attachment_upload"
            | "remove_queued_user_message"
            | "remove_newest_queued_user_message"
            | "remove_editable_queued_user_messages"
            | "resume_paused_work"
            | "cancel_paused_work"
            | "repair_resume"
            | "cancel_turn"
            | "resolve_interrupt"
            | "set_active_model"
            | "set_agent"
            | "set_llm_mode"
            | "set_session_llm_mode"
            | "set_approval_mode"
            | "set_delegation_recursion"
            | "set_sandbox"
            | "set_sandbox_escalation"
            | "set_preflight"
            | "set_trusted_only"
            | "set_redaction"
            | "set_tandem_models"
            | "cancel_schedule"
            | "prune"
            | "compact"
            | "pin"
            | "refresh_env"
            | "refresh_config"
    ) || (kind == "list_skills" && level != AuthzLevel::NoAccess)
        || (kind == "lsp_control" && matches!(level, AuthzLevel::Owner | AuthzLevel::Writer))
}

#[cfg(unix)]
fn authz_matrix_request(kind: &str, session_id: Uuid, project_root: &Path) -> Request {
    let root = project_root.to_string_lossy().into_owned();
    match kind {
        "attach" => attach_existing_request(session_id, project_root),
        "subagent_transcript" => Request::SubagentTranscript {
            session_id,
            task_call_id: "task-1".into(),
            label: "child".into(),
        },
        "send_user_message" => Request::SendUserMessage {
            text: "authz".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
        },
        "steer_delegation" => Request::SteerDelegation {
            session_id,
            task_call_id: "task-1".into(),
            label: "child".into(),
            message: "go".into(),
        },
        "begin_attachment_upload" => Request::BeginAttachmentUpload {
            mime: "text/plain".into(),
            byte_len: 1,
            sha256: "0".repeat(64),
            purpose: proto::AttachmentPurpose::UserMessageImage,
        },
        "upload_attachment_chunk" => Request::UploadAttachmentChunk {
            upload_id: Uuid::new_v4(),
            offset: 0,
            data_base64: String::new(),
        },
        "finish_attachment_upload" => Request::FinishAttachmentUpload {
            upload_id: Uuid::new_v4(),
        },
        "cancel_attachment_upload" => Request::CancelAttachmentUpload {
            upload_id: Uuid::new_v4(),
        },
        "remove_queued_user_message" => Request::RemoveQueuedUserMessage {
            queue_item_id: Uuid::new_v4(),
        },
        "remove_newest_queued_user_message" => {
            Request::RemoveNewestQueuedUserMessage { target_id: None }
        }
        "remove_editable_queued_user_messages" => {
            Request::RemoveEditableQueuedUserMessages { target_id: None }
        }
        "resume_paused_work" => Request::ResumePausedWork { session_id },
        "cancel_paused_work" => Request::CancelPausedWork { session_id },
        "repair_resume" => Request::RepairResume { session_id },
        "goal_status" => Request::GoalStatus { session_id },
        "set_goal_status" => Request::SetGoalStatus {
            session_id,
            status: proto::GoalStatus::Paused,
        },
        "clear_goal" => Request::ClearGoal { session_id },
        "list_assistants" => Request::ListAssistants,
        "create_assistant_session" => Request::CreateAssistantSession {
            name: "missing-assistant".into(),
            project_root: root,
            no_sandbox: false,
            env_snapshot: None,
        },
        "auto_title" => Request::AutoTitle { session_id },
        "export_session_data" => Request::ExportSessionData {
            session_id,
            kind: proto::ExportSessionKind::TranscriptJson,
            include_generated_artifacts: false,
            include_sensitive: false,
        },
        "curator" => Request::Curator {
            project_root: root,
            action: proto::CuratorAction::Status,
        },
        "cancel_turn" => Request::CancelTurn,
        "fs_list" => Request::FsList {
            project_root: root,
            path: ".".into(),
            show_hidden: false,
        },
        "fs_stat" => Request::FsStat {
            project_root: root,
            path: "missing.txt".into(),
        },
        "fs_read" => Request::FsRead {
            project_root: root,
            path: "missing.txt".into(),
            base64: false,
        },
        "fs_write" => Request::FsWrite {
            project_root: root,
            path: "authz.txt".into(),
            content: "authz".into(),
            base_hash: None,
        },
        "fs_create_dir" => Request::FsCreateDir {
            project_root: root,
            path: "authz-dir".into(),
        },
        "fs_rename" => Request::FsRename {
            project_root: root,
            from_path: "missing.txt".into(),
            to_path: "renamed.txt".into(),
        },
        "fs_delete" => Request::FsDelete {
            project_root: root,
            path: "missing.txt".into(),
        },
        "git_status" => Request::GitStatus { project_root: root },
        "git_diff_file" => Request::GitDiffFile {
            project_root: root,
            path: "missing.txt".into(),
        },
        "open_terminal" => Request::OpenTerminal {
            cwd: Some(
                project_root
                    .join("missing-cwd")
                    .to_string_lossy()
                    .into_owned(),
            ),
            cols: 80,
            rows: 24,
        },
        "attach_terminal" => Request::AttachTerminal {
            terminal_id: Uuid::new_v4(),
            cols: 80,
            rows: 24,
        },
        "terminal_input" => Request::TerminalInput {
            terminal_id: Uuid::new_v4(),
            bytes: b"x".to_vec(),
        },
        "terminal_resize" => Request::TerminalResize {
            terminal_id: Uuid::new_v4(),
            cols: 80,
            rows: 24,
        },
        "close_terminal" => Request::CloseTerminal {
            terminal_id: Uuid::new_v4(),
        },
        "lsp_control" => Request::LspControl {
            project_root: root,
            server_id: "rust-analyzer".into(),
            action: proto::LspControlAction::Check,
        },
        "resolve_interrupt" => Request::ResolveInterrupt {
            interrupt_id: Uuid::new_v4(),
            response: proto::ResolveResponse::Cancel,
        },
        "read_session_messages" => Request::ReadSessionMessages {
            session_id,
            before_seq: None,
            limit: 20,
        },
        "read_history_page" => Request::ReadHistoryPage {
            session_id,
            before_seq: None,
            limit: 20,
        },
        "archive_session" => Request::ArchiveSession {
            session_id,
            cascade: false,
        },
        "unarchive_session" => Request::UnarchiveSession { session_id },
        "fork_session" => Request::ForkSession {
            parent_session_id: session_id,
            fork_point_turn_id: None,
            ephemeral: false,
        },
        "discard_session" => Request::DiscardSession { session_id },
        "btw_create" => Request::CreateBtwFork {
            parent_session_id: session_id,
            tangent: false,
        },
        "btw_end" => Request::EndBtwFork {
            parent_session_id: session_id,
        },
        "rename_session" => Request::RenameSession {
            session_id,
            title: "authz".into(),
        },
        "share_session" => Request::ShareSession {
            session_id,
            shared: false,
        },
        "record_session_note" => Request::RecordSessionNote {
            session_id,
            text: "authz".into(),
        },
        "delete_session" => Request::DeleteSession {
            session_id,
            cascade: false,
        },
        "list_skills" => Request::ListSkills { project_root: root },
        "resource_snapshot" => Request::ResourceSnapshot,
        "promote_resource" => Request::PromoteResource {
            request_id: "missing".into(),
            session_id: None,
        },
        "create_scheduled_job" => Request::CreateScheduledJob {
            job: proto::ScheduledJobCreate {
                id: "job-authz".into(),
                owner: "system:test".into(),
                schedule: proto::ScheduledJobSchedule::Every { seconds: 60 },
                payload: proto::ScheduledJobPayload::Callback {
                    subsystem: "test".into(),
                },
                enabled: true,
                missed_run_policy: proto::MissedRunPolicy::Skip,
            },
        },
        "list_scheduled_jobs" => Request::ListScheduledJobs { owner: None },
        "delete_scheduled_job" => Request::DeleteScheduledJob {
            id: "job-authz".into(),
        },
        "set_scheduled_job_enabled" => Request::SetScheduledJobEnabled {
            id: "job-authz".into(),
            enabled: true,
        },
        "run_scheduled_job" => Request::RunScheduledJob {
            id: "job-authz".into(),
        },
        "list_agents" => Request::ListAgents,
        "list_models" => Request::ListModels { provider: None },
        "set_active_model" => Request::SetActiveModel {
            provider: "openai".into(),
            model: "gpt-5".into(),
            trigger: proto::ActiveModelSwitchTrigger::Daemon,
            reasoning_effort: None,
            thinking_mode: None,
        },
        "set_agent" => Request::SetAgent {
            name: "Build".into(),
        },
        "set_llm_mode" => Request::SetLlmMode { mode: None },
        "set_session_llm_mode" => Request::SetSessionLlmMode {
            mode: crate::config::extended::LlmMode::Normal,
        },
        "set_approval_mode" => Request::SetApprovalMode {
            mode: crate::config::extended::ApprovalMode::Manual,
        },
        "set_delegation_recursion" => Request::SetDelegationRecursion {
            enabled: false,
            default_depth: 1,
        },
        "set_sandbox" => Request::SetSandbox {
            mode: Some(crate::tools::sandbox_mode::SandboxMode::Sandbox),
            container_network_enabled: None,
        },
        "set_sandbox_escalation" => Request::SetSandboxEscalation { enabled: false },
        "set_preflight" => Request::SetPreflight { enabled: None },
        "set_trusted_only" => Request::SetTrustedOnly { enabled: None },
        "set_redaction" => Request::SetRedaction {
            scan_environment: Some(false),
            scan_dotenv: None,
            scan_ssh_keys: None,
        },
        "set_tandem_models" => Request::SetTandemModels { models: Vec::new() },
        "set_caffeinate" => Request::SetCaffeinate {
            mode: crate::daemon::caffeinate::CaffeinateMode::Off,
        },
        "cancel_schedule" => Request::CancelSchedule {
            job_id: "job-1".into(),
        },
        "prune" => Request::Prune,
        "compact" => Request::Compact,
        "pin" => Request::Pin {
            text: "remember".into(),
        },
        "store_flycockpit_credential" => Request::StoreFlycockpitCredential {
            credential: flycockpit_credential(),
        },
        "clear_flycockpit_credential" => Request::ClearFlycockpitCredential,
        "refresh_env" => Request::RefreshEnv {
            vars: HashMap::from([("COCKPIT_AUTHZ_MATRIX".into(), "1".into())]),
        },
        "refresh_config" => Request::RefreshConfig,
        "record_usage" => Request::RecordUsage {
            kind: proto::UsageKind::Slash,
            key: "/authz".into(),
            project_id: None,
        },
        "get_usage_counts" => Request::GetUsageCounts { project_id: None },
        "stats_rollup" => Request::StatsRollup {
            project_id: None,
            range: proto::StatsRange::Last7Days,
            by_role: false,
        },
        "guidance_estimate" => Request::GuidanceEstimate {
            project_root: root,
            provider: None,
            model: None,
        },
        "stop_daemon" => Request::StopDaemon {
            grace_secs: Some(1),
        },
        other => panic!("unhandled authz matrix request kind {other}"),
    }
}

#[cfg(unix)]
impl ReadonlyDispatchCaseKind {
    async fn assert_happy_socket_case(self) {
        match self {
            Self::FsList => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                std::fs::write(tmp.path().join("visible.txt"), "hello").unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::FsList {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: ".".into(),
                        show_hidden: false,
                    },
                )
                .await
                .expect("fs_list happy");
                let Response::FsList { entries, truncated } = response else {
                    panic!("expected FsList");
                };
                assert!(!truncated);
                assert!(entries.iter().any(|entry| entry.name == "visible.txt"));
            }
            Self::FsStat => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                std::fs::write(tmp.path().join("file.txt"), "hello").unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::FsStat {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: "file.txt".into(),
                    },
                )
                .await
                .expect("fs_stat happy");
                let Response::FsStat { entry } = response else {
                    panic!("expected FsStat");
                };
                assert_eq!(entry.name, "file.txt");
            }
            Self::FsRead => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                std::fs::write(tmp.path().join("file.txt"), "hello").unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::FsRead {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: "file.txt".into(),
                        base64: false,
                    },
                )
                .await
                .expect("fs_read happy");
                let Response::FsRead { content, .. } = response else {
                    panic!("expected FsRead");
                };
                assert_eq!(content.as_deref(), Some("hello"));
            }
            Self::GitStatus => {
                let ctx = test_ctx();
                let tmp = git_repo();
                std::fs::write(tmp.path().join("new.txt"), "hello").unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::GitStatus {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                    },
                )
                .await
                .expect("git_status happy");
                let Response::GitStatus { entries } = response else {
                    panic!("expected GitStatus");
                };
                assert!(entries.iter().any(|entry| entry.raw.contains("new.txt")));
            }
            Self::GitDiffFile => {
                let ctx = test_ctx();
                let tmp = git_repo();
                std::fs::write(tmp.path().join("tracked.txt"), "new\n").unwrap();
                run_git(tmp.path(), &["add", "-N", "tracked.txt"]);
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::GitDiffFile {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: "tracked.txt".into(),
                    },
                )
                .await
                .expect("git_diff_file happy");
                let Response::GitDiffFile { diff, truncated } = response else {
                    panic!("expected GitDiffFile");
                };
                assert!(!truncated);
                assert!(diff.contains("+new"));
            }
            Self::ListSessions => {
                let ctx = test_ctx();
                let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::ListSessions {
                        project_id: None,
                        parent_session_id: None,
                    },
                )
                .await
                .expect("list_sessions happy");
                let Response::Sessions { sessions } = response else {
                    panic!("expected Sessions");
                };
                assert!(
                    sessions
                        .iter()
                        .any(|summary| summary.session_id == session.session_id)
                );
            }
            Self::ReadSessionMessages => {
                let ctx = test_ctx();
                let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
                let seq = ctx
                    .db
                    .insert_session_event(
                        session.session_id,
                        crate::db::session_log::SessionEventKind::UserMessage,
                        Some("Build"),
                        None,
                        &serde_json::json!({"text": "hello"}),
                    )
                    .unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::ReadSessionMessages {
                        session_id: session.session_id,
                        before_seq: None,
                        limit: 20,
                    },
                )
                .await
                .expect("read_session_messages happy");
                let Response::SessionMessages { messages, .. } = response else {
                    panic!("expected SessionMessages");
                };
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].seq, seq);
            }
            Self::ReadHistoryPage => {
                let ctx = test_ctx();
                let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
                let seq = ctx
                    .db
                    .insert_session_event(
                        session.session_id,
                        crate::db::session_log::SessionEventKind::UserMessage,
                        Some("Build"),
                        None,
                        &serde_json::json!({"text": "hello"}),
                    )
                    .unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::ReadHistoryPage {
                        session_id: session.session_id,
                        before_seq: None,
                        limit: 20,
                    },
                )
                .await
                .expect("read_history_page happy");
                let Response::HistoryPage { entries, .. } = response else {
                    panic!("expected HistoryPage");
                };
                assert_eq!(entries.len(), 1);
                assert!(
                    matches!(&entries[0], proto::HistoryEntry::User { seq: got, .. } if *got == seq)
                );
            }
            Self::SessionLiveStatus => {
                let ctx = test_ctx();
                let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
                insert_hung_worker(&ctx, session.session_id);
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::SessionLiveStatus {
                        session_ids: vec![session.session_id],
                    },
                )
                .await
                .expect("session_live_status happy");
                let Response::SessionLiveStatus { statuses } = response else {
                    panic!("expected SessionLiveStatus");
                };
                assert_eq!(statuses.len(), 1);
                assert_eq!(statuses[0].session_id, session.session_id);
            }
            Self::GoalStatus => {
                let ctx = test_ctx();
                let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
                ctx.db
                    .create_session_goal(
                        session.session_id,
                        &session.project_id,
                        "ship status rpc",
                        Some("context"),
                        Some(100),
                    )
                    .unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::GoalStatus {
                        session_id: session.session_id,
                    },
                )
                .await
                .expect("goal_status happy");
                let Response::GoalStatus { goal: Some(goal) } = response else {
                    panic!("expected GoalStatus with goal");
                };
                assert_eq!(goal.session_id, session.session_id);
                assert_eq!(goal.objective, "ship status rpc");
                assert_eq!(goal.status, proto::GoalStatus::Active);
            }
            Self::ListSkills => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                ctx.db
                    .set_workspace_trust(
                        tmp.path(),
                        crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                    )
                    .unwrap();
                let response = dispatch_matrix_request_after(
                    &ctx,
                    vec![Request::Attach {
                        session_id: None,
                        since_seq: None,
                        project_root: Some(tmp.path().to_string_lossy().into_owned()),
                        no_sandbox: false,
                        interactive: true,
                        model_override: None,
                        client_protocol_version: proto::PROTOCOL_VERSION,
                        env_snapshot: None,
                        env_policy: EnvDriftPolicy::Daemon,
                    }],
                    Request::ListSkills {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                    },
                )
                .await
                .expect("list_skills happy");
                let Response::Skills { skills } = response else {
                    panic!("expected Skills");
                };
                assert!(skills.is_empty());
            }
            Self::DaemonStatus => {
                let ctx = test_ctx();
                let response = dispatch_matrix_request(&ctx, Request::DaemonStatus)
                    .await
                    .expect("daemon_status happy");
                let Response::DaemonStatus {
                    pid,
                    protocol_version,
                    ..
                } = response
                else {
                    panic!("expected DaemonStatus");
                };
                assert_eq!(pid, std::process::id());
                assert_eq!(protocol_version, proto::PROTOCOL_VERSION);
            }
            Self::GuidanceEstimate => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::GuidanceEstimate {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        provider: None,
                        model: None,
                    },
                )
                .await
                .expect("guidance_estimate happy");
                let Response::GuidanceEstimate {
                    file,
                    tokens,
                    system_tokens,
                    ..
                } = response
                else {
                    panic!("expected GuidanceEstimate");
                };
                assert_eq!(file, None);
                assert_eq!(tokens, 0);
                assert!(system_tokens > 0);
            }
        }
    }

    async fn assert_malformed_socket_case(self) {
        match self {
            Self::FsList => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                let err = dispatch_matrix_request(
                    &ctx,
                    Request::FsList {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: "missing".into(),
                        show_hidden: false,
                    },
                )
                .await
                .expect_err("fs_list missing path");
                assert_eq!(err.code, ErrorCode::BadRequest);
            }
            Self::FsStat | Self::FsRead => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                let request = match self {
                    Self::FsStat => Request::FsStat {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: "../outside".into(),
                    },
                    Self::FsRead => Request::FsRead {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: "../outside".into(),
                        base64: false,
                    },
                    _ => unreachable!(),
                };
                let err = dispatch_matrix_request(&ctx, request)
                    .await
                    .expect_err("fs traversal is rejected");
                assert_eq!(err.code, ErrorCode::PathOutsideRoot);
            }
            Self::GitStatus => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                let err = dispatch_matrix_request(
                    &ctx,
                    Request::GitStatus {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                    },
                )
                .await
                .expect_err("git_status outside a repository");
                assert_eq!(err.code, ErrorCode::BadRequest);
            }
            Self::GitDiffFile => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                let err = dispatch_matrix_request(
                    &ctx,
                    Request::GitDiffFile {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                        path: "../outside".into(),
                    },
                )
                .await
                .expect_err("git_diff_file traversal is rejected");
                assert_eq!(err.code, ErrorCode::PathOutsideRoot);
            }
            Self::ListSessions => {
                let ctx = test_ctx();
                ctx.db.create_session("visible", "/repo", "Build").unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::ListSessions {
                        project_id: Some("missing-project".into()),
                        parent_session_id: None,
                    },
                )
                .await
                .expect("list_sessions invalid filter is typed empty response");
                let Response::Sessions { sessions } = response else {
                    panic!("expected Sessions");
                };
                assert!(sessions.is_empty());
            }
            Self::ReadSessionMessages => {
                let ctx = test_ctx();
                let unknown_session_id = Uuid::new_v4();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::ReadSessionMessages {
                        session_id: unknown_session_id,
                        before_seq: None,
                        limit: 20,
                    },
                )
                .await
                .expect("unknown session messages return an empty typed page");
                let Response::SessionMessages {
                    session_id,
                    messages,
                    has_more,
                } = response
                else {
                    panic!("expected SessionMessages");
                };
                assert_eq!(session_id, unknown_session_id);
                assert!(messages.is_empty());
                assert!(!has_more);
            }
            Self::ReadHistoryPage => {
                let ctx = test_ctx();
                let unknown_session_id = Uuid::new_v4();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::ReadHistoryPage {
                        session_id: unknown_session_id,
                        before_seq: None,
                        limit: 20,
                    },
                )
                .await
                .expect("unknown history page returns an empty typed page");
                let Response::HistoryPage {
                    session_id,
                    entries,
                    has_more,
                    oldest_seq,
                } = response
                else {
                    panic!("expected HistoryPage");
                };
                assert_eq!(session_id, unknown_session_id);
                assert!(entries.is_empty());
                assert!(!has_more);
                assert_eq!(oldest_seq, None);
            }
            Self::SessionLiveStatus => {
                let ctx = test_ctx();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::SessionLiveStatus {
                        session_ids: vec![Uuid::new_v4()],
                    },
                )
                .await
                .expect("unknown live status is typed empty response");
                let Response::SessionLiveStatus { statuses } = response else {
                    panic!("expected SessionLiveStatus");
                };
                assert!(statuses.is_empty());
            }
            Self::GoalStatus => {
                let ctx = test_ctx();
                let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::GoalStatus {
                        session_id: session.session_id,
                    },
                )
                .await
                .expect("goal_status without an open goal is typed none");
                assert!(matches!(response, Response::GoalStatus { goal: None }));
            }
            Self::ListSkills => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                let err = dispatch_matrix_request(
                    &ctx,
                    Request::ListSkills {
                        project_root: tmp.path().to_string_lossy().into_owned(),
                    },
                )
                .await
                .expect_err("list_skills requires attachment");
                assert_eq!(err.code, ErrorCode::NotAttached);
            }
            Self::DaemonStatus => {
                let ctx = test_ctx();
                let request_id = Uuid::new_v4();
                let err = dispatch_matrix_raw_line(
                    &ctx,
                    request_id,
                    serde_json::json!({
                        "v": proto::PROTOCOL_VERSION + 1,
                        "kind": "req",
                        "id": request_id,
                        "request": "daemon_status",
                    })
                    .to_string(),
                )
                .await
                .expect_err("daemon_status malformed protocol version");
                assert_eq!(err.code, ErrorCode::ProtocolVersion);
            }
            Self::GuidanceEstimate => {
                let ctx = test_ctx();
                let tmp = tempfile::tempdir().unwrap();
                let missing = tmp.path().join("missing");
                let response = dispatch_matrix_request(
                    &ctx,
                    Request::GuidanceEstimate {
                        project_root: missing.to_string_lossy().into_owned(),
                        provider: Some("missing-provider".into()),
                        model: Some("missing-model".into()),
                    },
                )
                .await
                .expect("guidance estimate tolerates absent guidance roots");
                let Response::GuidanceEstimate { file, tokens, .. } = response else {
                    panic!("expected GuidanceEstimate");
                };
                assert_eq!(file, None);
                assert_eq!(tokens, 0);
            }
        }
    }
}

#[cfg(unix)]
async fn assert_mutating_happy_socket_case(case: MutatingDispatchCase) {
    match case.effect_class {
        DispatchEffectClass::Durable
        | DispatchEffectClass::InMemory
        | DispatchEffectClass::DriverForwarded => {}
    }
    match case.kind {
        "attach" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            ctx.db
                .set_workspace_trust(
                    tmp.path(),
                    crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                )
                .unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::Attach {
                    session_id: None,
                    since_seq: None,
                    project_root: Some(tmp.path().to_string_lossy().into_owned()),
                    no_sandbox: false,
                    interactive: true,
                    model_override: None,
                    client_protocol_version: proto::PROTOCOL_VERSION,
                    env_snapshot: None,
                    env_policy: EnvDriftPolicy::Daemon,
                },
            )
            .await
            .expect("attach happy");
            let Response::Attached { session_id, .. } = response else {
                panic!("expected Attached");
            };
            assert!(ctx.registry.live_handle(session_id).is_some());
        }
        "begin_attachment_upload"
        | "upload_attachment_chunk"
        | "finish_attachment_upload"
        | "cancel_attachment_upload" => {
            assert_attachment_mutating_happy(case.kind).await;
        }
        "fs_write" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::FsWrite {
                    project_root: tmp.path().to_string_lossy().into_owned(),
                    path: "file.txt".into(),
                    content: "written".into(),
                    base_hash: None,
                },
            )
            .await
            .expect("fs_write happy");
            assert!(matches!(response, Response::FsWrite { .. }));
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("file.txt")).unwrap(),
                "written"
            );
        }
        "fs_create_dir" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::FsCreateDir {
                    project_root: tmp.path().to_string_lossy().into_owned(),
                    path: "new-dir".into(),
                },
            )
            .await
            .expect("fs_create_dir happy");
            assert!(matches!(response, Response::Ack));
            assert!(tmp.path().join("new-dir").is_dir());
        }
        "fs_rename" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("old.txt"), "move").unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::FsRename {
                    project_root: tmp.path().to_string_lossy().into_owned(),
                    from_path: "old.txt".into(),
                    to_path: "new.txt".into(),
                },
            )
            .await
            .expect("fs_rename happy");
            assert!(matches!(response, Response::Ack));
            assert!(!tmp.path().join("old.txt").exists());
            assert_eq!(
                std::fs::read_to_string(tmp.path().join("new.txt")).unwrap(),
                "move"
            );
        }
        "fs_delete" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("gone.txt"), "delete").unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::FsDelete {
                    project_root: tmp.path().to_string_lossy().into_owned(),
                    path: "gone.txt".into(),
                },
            )
            .await
            .expect("fs_delete happy");
            assert!(matches!(response, Response::Ack));
            assert!(!tmp.path().join("gone.txt").exists());
        }
        "open_terminal" | "close_terminal" => assert_terminal_mutating_happy(case.kind).await,
        "resume_paused_work" | "cancel_paused_work" => {
            assert_paused_work_mutating_happy(case.kind).await;
        }
        "set_goal_status" | "clear_goal" => assert_goal_mutating_happy(case.kind).await,
        "create_assistant_session" => assert_create_assistant_session_happy().await,
        "auto_title" => assert_auto_title_mutating_happy().await,
        "curator" => assert_curator_mutating_happy().await,
        "archive_session"
        | "unarchive_session"
        | "fork_session"
        | "discard_session"
        | "btw_create"
        | "btw_end"
        | "rename_session"
        | "share_session"
        | "record_session_note"
        | "delete_session" => assert_session_db_mutating_happy(case.kind).await,
        "promote_resource" => assert_promote_resource_happy().await,
        "create_scheduled_job"
        | "delete_scheduled_job"
        | "set_scheduled_job_enabled"
        | "run_scheduled_job" => assert_scheduler_dispatch_happy(case.kind).await,
        "set_approval_mode"
        | "set_sandbox"
        | "set_sandbox_escalation"
        | "set_caffeinate"
        | "refresh_env"
        | "record_usage"
        | "store_flycockpit_credential"
        | "clear_flycockpit_credential"
        | "stop_daemon"
        | "lsp_control" => assert_in_memory_or_global_mutating_happy(case.kind).await,
        "send_user_message"
        | "steer_delegation"
        | "remove_queued_user_message"
        | "remove_newest_queued_user_message"
        | "remove_editable_queued_user_messages"
        | "repair_resume"
        | "cancel_turn"
        | "resolve_interrupt"
        | "set_active_model"
        | "set_agent"
        | "set_llm_mode"
        | "set_session_llm_mode"
        | "set_delegation_recursion"
        | "set_preflight"
        | "set_trusted_only"
        | "set_redaction"
        | "set_tandem_models"
        | "refresh_config"
        | "cancel_schedule"
        | "prune"
        | "compact"
        | "pin" => assert_worker_delivery_happy(case.kind).await,
        other => panic!("unhandled mutating happy case {other}"),
    }
}

#[cfg(unix)]
async fn assert_mutating_malformed_socket_case(case: MutatingDispatchCase) {
    match case.kind {
        "attach" => {
            let ctx = test_ctx();
            let err = dispatch_matrix_request(
                &ctx,
                Request::Attach {
                    session_id: Some(Uuid::new_v4()),
                    since_seq: None,
                    project_root: None,
                    no_sandbox: false,
                    interactive: true,
                    model_override: None,
                    client_protocol_version: proto::PROTOCOL_VERSION,
                    env_snapshot: None,
                    env_policy: EnvDriftPolicy::Daemon,
                },
            )
            .await
            .expect_err("unknown attach session");
            assert_eq!(err.code, ErrorCode::UnknownSession);
            assert!(ctx.registry.active_session_ids().is_empty());
        }
        "begin_attachment_upload"
        | "upload_attachment_chunk"
        | "finish_attachment_upload"
        | "cancel_attachment_upload" => {
            assert_attachment_mutating_malformed(case.kind).await;
        }
        "fs_write" | "fs_create_dir" | "fs_rename" | "fs_delete" => {
            assert_fs_mutating_malformed(case.kind).await;
        }
        "open_terminal" | "close_terminal" => {
            assert_terminal_mutating_malformed(case.kind).await;
        }
        "resume_paused_work" | "cancel_paused_work" => {
            let ctx = test_ctx();
            let response = dispatch_matrix_request(
                &ctx,
                match case.kind {
                    "resume_paused_work" => Request::ResumePausedWork {
                        session_id: Uuid::new_v4(),
                    },
                    "cancel_paused_work" => Request::CancelPausedWork {
                        session_id: Uuid::new_v4(),
                    },
                    _ => unreachable!(),
                },
            )
            .await
            .expect("unknown paused work is typed no-op");
            assert!(matches!(response, Response::Ack));
            assert!(ctx.db.paused_session_work_all().unwrap().is_empty());
        }
        "set_goal_status" | "clear_goal" => assert_goal_mutating_malformed(case.kind).await,
        "create_assistant_session" => {
            let ctx = test_ctx();
            let err = dispatch_matrix_request(
                &ctx,
                Request::CreateAssistantSession {
                    name: "missing-assistant".into(),
                    project_root: "/repo".into(),
                    no_sandbox: false,
                    env_snapshot: None,
                },
            )
            .await
            .expect_err("missing assistant rejects session creation");
            assert_eq!(err.code, ErrorCode::BadRequest);
            assert!(ctx.registry.active_session_ids().is_empty());
        }
        "auto_title" => assert_auto_title_mutating_malformed().await,
        "curator" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let err = dispatch_matrix_request(
                &ctx,
                Request::Curator {
                    project_root: tmp.path().to_string_lossy().into_owned(),
                    action: proto::CuratorAction::Status,
                },
            )
            .await
            .expect_err("curator rejects untrusted project");
            assert_eq!(err.code, ErrorCode::WorkspaceTrust);
        }
        "archive_session"
        | "unarchive_session"
        | "fork_session"
        | "discard_session"
        | "btw_create"
        | "btw_end"
        | "rename_session"
        | "share_session"
        | "record_session_note"
        | "delete_session" => assert_session_db_mutating_malformed(case.kind).await,
        "promote_resource" => {
            let ctx = persistent_test_ctx();
            let response = dispatch_matrix_request(
                &ctx,
                Request::PromoteResource {
                    request_id: "missing".into(),
                    session_id: None,
                },
            )
            .await
            .expect("missing resource request is typed non-applied response");
            let Response::PromoteResourceResult { status, .. } = response else {
                panic!("expected PromoteResourceResult");
            };
            assert_eq!(status, proto::ResourcePromoteStatus::NotFound);
        }
        "create_scheduled_job"
        | "delete_scheduled_job"
        | "set_scheduled_job_enabled"
        | "run_scheduled_job" => assert_scheduler_shared_only_dispatch(case.kind).await,
        "set_approval_mode"
        | "set_sandbox"
        | "set_sandbox_escalation"
        | "refresh_env"
        | "refresh_config"
        | "lsp_control"
        | "send_user_message"
        | "remove_queued_user_message"
        | "remove_newest_queued_user_message"
        | "remove_editable_queued_user_messages"
        | "repair_resume"
        | "cancel_turn"
        | "resolve_interrupt"
        | "set_active_model"
        | "set_agent"
        | "set_llm_mode"
        | "set_session_llm_mode"
        | "set_delegation_recursion"
        | "set_preflight"
        | "set_trusted_only"
        | "set_redaction"
        | "set_tandem_models"
        | "cancel_schedule"
        | "prune"
        | "compact"
        | "pin" => assert_attached_required_malformed(case.kind).await,
        "steer_delegation" => assert_steer_delegation_malformed().await,
        "set_caffeinate" => {
            let ctx = test_ctx();
            let response = dispatch_matrix_request(
                &ctx,
                Request::SetCaffeinate {
                    mode: crate::daemon::caffeinate::CaffeinateMode::Off,
                },
            )
            .await
            .expect("caffeinate off is typed no-op when already off");
            let Response::CaffeinateState { active, .. } = response else {
                panic!("expected CaffeinateState");
            };
            assert!(!active);
        }
        "record_usage" => {
            let ctx = test_ctx();
            let err = dispatch_matrix_request(
                &ctx,
                Request::RecordUsage {
                    kind: proto::UsageKind::Slash,
                    key: "   ".into(),
                    project_id: None,
                },
            )
            .await
            .expect_err("empty usage key is rejected");
            assert_eq!(err.code, ErrorCode::BadRequest);
            let counts = ctx.db.usage_counts("slash", None, 0).unwrap();
            assert!(counts.is_empty());
        }
        "store_flycockpit_credential" | "clear_flycockpit_credential" => {
            let ctx = test_ctx();
            let request = if case.kind == "store_flycockpit_credential" {
                Request::StoreFlycockpitCredential {
                    credential: flycockpit_credential(),
                }
            } else {
                Request::ClearFlycockpitCredential
            };
            let err = dispatch_matrix_request(&ctx, request)
                .await
                .expect_err("ephemeral credential writes rejected");
            assert_eq!(err.code, ErrorCode::BadRequest);
        }
        "stop_daemon" => {
            let ctx = test_ctx();
            let response = dispatch_matrix_request(
                &ctx,
                Request::StopDaemon {
                    grace_secs: Some(1),
                },
            )
            .await
            .expect("first stop starts drain");
            assert!(matches!(response, Response::Ack));
            let response = dispatch_matrix_request(
                &ctx,
                Request::StopDaemon {
                    grace_secs: Some(0),
                },
            )
            .await
            .expect("second stop forces drain");
            assert!(matches!(response, Response::Ack));
            wait_for_shutdown_phase(&ctx, ShutdownPhase::Forced).await;
        }
        other => panic!("unhandled mutating malformed case {other}"),
    }
}

#[cfg(unix)]
fn live_worker_with_receiver(
    ctx: &Arc<DaemonContext>,
    project_root: &Path,
) -> (Uuid, tokio::sync::mpsc::Receiver<SessionWork>) {
    ctx.db
        .set_workspace_trust(
            project_root,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let row = ctx
        .db
        .create_session("p", project_root.to_str().unwrap(), "Build")
        .unwrap();
    let session = Arc::new(
        Session::resume(ctx.db.clone(), row.session_id)
            .unwrap()
            .expect("session row"),
    );
    let (handle, work_rx) =
        SessionWorkerHandle::test_handle_with_receiver(session, ctx.registry.locks());
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);
    (row.session_id, work_rx)
}

#[cfg(unix)]
async fn dispatch_attached_worker_request(
    ctx: &Arc<DaemonContext>,
    project_root: &Path,
    session_id: Uuid,
    mut work_rx: tokio::sync::mpsc::Receiver<SessionWork>,
    request: Request,
    observe: impl FnOnce(SessionWork),
) -> std::result::Result<Response, ErrorPayload> {
    let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
    let mut client = ProtoStream::new(client_stream);
    let server = tokio::spawn(handle_client_transport(server_stream, ctx.clone()));
    match recv_body(&mut client).await {
        Body::Response { id, response } => {
            assert_eq!(id, Uuid::nil());
            assert!(matches!(*response, Response::DaemonStatus { .. }));
        }
        other => panic!("expected daemon hello, got {other:?}"),
    }
    let attach_id = Uuid::new_v4();
    client
        .send(&Envelope::request(
            attach_id,
            Request::Attach {
                session_id: Some(session_id),
                since_seq: None,
                project_root: Some(project_root.to_string_lossy().into_owned()),
                no_sandbox: false,
                interactive: true,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
        ))
        .await
        .expect("send attach");
    recv_dispatch_matrix_response(&mut client, attach_id)
        .await
        .expect("attach succeeds");
    let hydration = tokio::time::timeout(std::time::Duration::from_secs(2), work_rx.recv())
        .await
        .expect("attach hydration delivered")
        .expect("attach hydration present");
    assert!(
        matches!(hydration, SessionWork::RepublishQueue),
        "unexpected attach hydration: {hydration:?}"
    );

    let id = Uuid::new_v4();
    client
        .send(&Envelope::request(id, request))
        .await
        .expect("send worker request");
    let work = tokio::time::timeout(std::time::Duration::from_secs(2), work_rx.recv())
        .await
        .expect("worker command delivered")
        .expect("worker command present");
    observe(work);
    let result = recv_dispatch_matrix_response(&mut client, id).await;
    drop(client);
    server
        .await
        .expect("server task joins")
        .expect("server task succeeds");
    result
}

#[cfg(unix)]
fn proto_queue_item(text: &str) -> proto::QueueItem {
    proto::QueueItem {
        id: Uuid::new_v4(),
        status: proto::QueueItemStatus::Queued,
        text: text.to_string(),
        display_text: None,
        target: proto::QueueTarget::default(),
    }
}

#[cfg(unix)]
async fn assert_worker_delivery_happy(kind: &str) {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (session_id, work_rx) = live_worker_with_receiver(&ctx, tmp.path());
    let request = match kind {
        "send_user_message" => Request::SendUserMessage {
            text: "hello worker".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
        },
        "steer_delegation" => Request::SteerDelegation {
            session_id,
            task_call_id: "task-1".into(),
            label: "child".into(),
            message: "steer".into(),
        },
        "remove_queued_user_message" => Request::RemoveQueuedUserMessage {
            queue_item_id: Uuid::from_u128(1),
        },
        "remove_newest_queued_user_message" => Request::RemoveNewestQueuedUserMessage {
            target_id: Some("root".into()),
        },
        "remove_editable_queued_user_messages" => Request::RemoveEditableQueuedUserMessages {
            target_id: Some("root".into()),
        },
        "repair_resume" => Request::RepairResume { session_id },
        "cancel_turn" => Request::CancelTurn,
        "resolve_interrupt" => Request::ResolveInterrupt {
            interrupt_id: Uuid::from_u128(2),
            response: proto::ResolveResponse::Cancel,
        },
        "set_active_model" => Request::SetActiveModel {
            provider: "openai".into(),
            model: "gpt-5".into(),
            trigger: proto::ActiveModelSwitchTrigger::Daemon,
            reasoning_effort: None,
            thinking_mode: None,
        },
        "set_agent" => Request::SetAgent {
            name: "Build".into(),
        },
        "set_llm_mode" => Request::SetLlmMode {
            mode: Some(crate::config::extended::LlmMode::Defensive),
        },
        "set_session_llm_mode" => Request::SetSessionLlmMode {
            mode: crate::config::extended::LlmMode::Normal,
        },
        "set_delegation_recursion" => Request::SetDelegationRecursion {
            enabled: true,
            default_depth: 3,
        },
        "set_preflight" => Request::SetPreflight {
            enabled: Some(true),
        },
        "set_trusted_only" => Request::SetTrustedOnly {
            enabled: Some(true),
        },
        "set_redaction" => Request::SetRedaction {
            scan_environment: Some(false),
            scan_dotenv: Some(true),
            scan_ssh_keys: None,
        },
        "set_tandem_models" => Request::SetTandemModels {
            models: vec![("openai".into(), "gpt-5".into())],
        },
        "refresh_config" => Request::RefreshConfig,
        "cancel_schedule" => Request::CancelSchedule {
            job_id: "job-1".into(),
        },
        "prune" => Request::Prune,
        "compact" => Request::Compact,
        "pin" => Request::Pin {
            text: "remember this".into(),
        },
        other => panic!("unexpected worker case {other}"),
    };
    let response =
        dispatch_attached_worker_request(&ctx, tmp.path(), session_id, work_rx, request, |work| {
            match (kind, work) {
                (
                    "send_user_message",
                    SessionWork::UserMessage {
                        submission,
                        respond_to,
                    },
                ) => {
                    assert_eq!(submission.text, "hello worker");
                    let item = proto_queue_item(&submission.text);
                    respond_to.send((item.clone(), vec![item])).unwrap();
                }
                (
                    "steer_delegation",
                    SessionWork::SteerDelegation {
                        task_call_id,
                        label,
                        message,
                        respond_to,
                        ..
                    },
                ) => {
                    assert_eq!(task_call_id, "task-1");
                    assert_eq!(label, "child");
                    assert_eq!(message, "steer");
                    respond_to
                        .send(proto::DelegationSteerResult::queued(
                            task_call_id,
                            label,
                            1,
                            "owner".into(),
                            false,
                        ))
                        .unwrap();
                }
                (
                    "remove_queued_user_message",
                    SessionWork::RemoveQueuedUserMessage {
                        queue_item_id,
                        respond_to,
                    },
                ) => {
                    assert_eq!(queue_item_id, Uuid::from_u128(1));
                    respond_to
                        .send(proto::RemoveQueuedUserMessageResult {
                            applied: true,
                            reason: proto::RemoveQueuedUserMessageReason::Removed,
                            removed_item: Some(proto_queue_item("removed")),
                            queue: Vec::new(),
                        })
                        .unwrap();
                }
                (
                    "remove_newest_queued_user_message",
                    SessionWork::RemoveNewestQueuedUserMessage {
                        target_id,
                        respond_to,
                    },
                ) => {
                    assert_eq!(target_id.as_deref(), Some("root"));
                    respond_to
                        .send(proto::RemoveQueuedUserMessageResult {
                            applied: false,
                            reason: proto::RemoveQueuedUserMessageReason::NotFound,
                            removed_item: None,
                            queue: Vec::new(),
                        })
                        .unwrap();
                }
                (
                    "remove_editable_queued_user_messages",
                    SessionWork::RemoveEditableQueuedUserMessages {
                        target_id,
                        respond_to,
                    },
                ) => {
                    assert_eq!(target_id.as_deref(), Some("root"));
                    respond_to
                        .send(proto::RemoveQueuedUserMessagesResult {
                            applied: true,
                            reason: proto::RemoveQueuedUserMessageReason::Removed,
                            removed_items: vec![proto_queue_item("removed")],
                            queue: Vec::new(),
                        })
                        .unwrap();
                }
                ("repair_resume", SessionWork::RepairResume { respond_to }) => {
                    respond_to.send(Ok(())).unwrap();
                }
                ("cancel_turn", SessionWork::Cancel) => {}
                (
                    "resolve_interrupt",
                    SessionWork::ResolveInterrupt {
                        interrupt_id,
                        response,
                    },
                ) => {
                    assert_eq!(interrupt_id, Uuid::from_u128(2));
                    assert!(matches!(response, proto::ResolveResponse::Cancel));
                }
                (
                    "set_active_model",
                    SessionWork::SetActiveModel {
                        provider,
                        model,
                        trigger,
                        reasoning_effort,
                        thinking_mode,
                    },
                ) => {
                    assert_eq!(provider, "openai");
                    assert_eq!(model, "gpt-5");
                    assert!(matches!(
                        trigger,
                        crate::session::ModelSwitchTrigger::Daemon
                    ));
                    assert_eq!(reasoning_effort, None);
                    assert_eq!(thinking_mode, None);
                }
                ("set_agent", SessionWork::SetAgent { name }) => {
                    assert_eq!(name, "Build");
                }
                ("set_llm_mode", SessionWork::SetLlmMode { mode }) => {
                    assert_eq!(mode, Some(crate::config::extended::LlmMode::Defensive));
                }
                ("set_session_llm_mode", SessionWork::SetSessionLlmMode { mode }) => {
                    assert_eq!(mode, crate::config::extended::LlmMode::Normal);
                }
                (
                    "set_delegation_recursion",
                    SessionWork::SetDelegationRecursion {
                        enabled,
                        default_depth,
                    },
                ) => {
                    assert!(enabled);
                    assert_eq!(default_depth, 3);
                }
                ("set_preflight", SessionWork::SetPreflight { enabled }) => {
                    assert_eq!(enabled, Some(true));
                }
                ("set_trusted_only", SessionWork::SetTrustedOnly { enabled }) => {
                    assert_eq!(enabled, Some(true));
                }
                (
                    "set_redaction",
                    SessionWork::SetRedaction {
                        scan_environment,
                        scan_dotenv,
                        scan_ssh_keys,
                    },
                ) => {
                    assert_eq!(scan_environment, Some(false));
                    assert_eq!(scan_dotenv, Some(true));
                    assert_eq!(scan_ssh_keys, None);
                }
                ("set_tandem_models", SessionWork::SetTandemModels { models }) => {
                    assert_eq!(models, vec![("openai".to_string(), "gpt-5".to_string())]);
                }
                (
                    "refresh_config",
                    SessionWork::ReplaceConfigSnapshot {
                        snapshot,
                        respond_to,
                    },
                ) => {
                    assert_eq!(snapshot.generation, 0);
                    respond_to.send(1).unwrap();
                }
                ("cancel_schedule", SessionWork::CancelSchedule { job_id }) => {
                    assert_eq!(job_id, "job-1");
                }
                ("prune", SessionWork::Prune) | ("compact", SessionWork::Compact) => {}
                ("pin", SessionWork::Pin { text }) => {
                    assert_eq!(text, "remember this");
                }
                (kind, work) => panic!("unexpected worker delivery for {kind}: {work:?}"),
            }
        })
        .await
        .expect("worker dispatch succeeds");
    match kind {
        "send_user_message" => assert!(matches!(response, Response::UserMessageQueued { .. })),
        "steer_delegation" => assert!(matches!(response, Response::DelegationSteer { .. })),
        "remove_queued_user_message" | "remove_newest_queued_user_message" => {
            assert!(matches!(
                response,
                Response::RemoveQueuedUserMessageResult { .. }
            ));
        }
        "remove_editable_queued_user_messages" => {
            assert!(matches!(
                response,
                Response::RemoveQueuedUserMessagesResult { .. }
            ));
        }
        "set_delegation_recursion" => {
            assert!(matches!(
                response,
                Response::DelegationRecursionState { .. }
            ));
        }
        _ => assert!(matches!(response, Response::Ack), "{kind}: {response:?}"),
    }
}

#[cfg(unix)]
async fn assert_attached_required_malformed(kind: &str) {
    let ctx = test_ctx();
    let request = match kind {
        "send_user_message" => Request::SendUserMessage {
            text: "detached".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
        },
        "remove_queued_user_message" => Request::RemoveQueuedUserMessage {
            queue_item_id: Uuid::new_v4(),
        },
        "remove_newest_queued_user_message" => {
            Request::RemoveNewestQueuedUserMessage { target_id: None }
        }
        "remove_editable_queued_user_messages" => {
            Request::RemoveEditableQueuedUserMessages { target_id: None }
        }
        "repair_resume" => Request::RepairResume {
            session_id: Uuid::new_v4(),
        },
        "cancel_turn" => Request::CancelTurn,
        "resolve_interrupt" => Request::ResolveInterrupt {
            interrupt_id: Uuid::new_v4(),
            response: proto::ResolveResponse::Cancel,
        },
        "set_active_model" => Request::SetActiveModel {
            provider: "openai".into(),
            model: "gpt-5".into(),
            trigger: proto::ActiveModelSwitchTrigger::Daemon,
            reasoning_effort: None,
            thinking_mode: None,
        },
        "set_agent" => Request::SetAgent {
            name: "Build".into(),
        },
        "set_llm_mode" => Request::SetLlmMode { mode: None },
        "set_session_llm_mode" => Request::SetSessionLlmMode {
            mode: crate::config::extended::LlmMode::Normal,
        },
        "set_approval_mode" => Request::SetApprovalMode {
            mode: crate::config::extended::ApprovalMode::Manual,
        },
        "set_delegation_recursion" => Request::SetDelegationRecursion {
            enabled: false,
            default_depth: 1,
        },
        "set_sandbox" => Request::SetSandbox {
            mode: Some(crate::tools::sandbox_mode::SandboxMode::Sandbox),
            container_network_enabled: None,
        },
        "set_sandbox_escalation" => Request::SetSandboxEscalation { enabled: false },
        "set_preflight" => Request::SetPreflight { enabled: None },
        "set_trusted_only" => Request::SetTrustedOnly { enabled: None },
        "set_redaction" => Request::SetRedaction {
            scan_environment: Some(false),
            scan_dotenv: None,
            scan_ssh_keys: None,
        },
        "set_tandem_models" => Request::SetTandemModels { models: Vec::new() },
        "cancel_schedule" => Request::CancelSchedule {
            job_id: "job-1".into(),
        },
        "prune" => Request::Prune,
        "compact" => Request::Compact,
        "pin" => Request::Pin { text: "x".into() },
        "refresh_env" => Request::RefreshEnv {
            vars: HashMap::from([("PATH".into(), "/bin".into())]),
        },
        "refresh_config" => Request::RefreshConfig,
        "lsp_control" => Request::LspControl {
            project_root: std::env::temp_dir().to_string_lossy().into_owned(),
            server_id: "rust-analyzer".into(),
            action: proto::LspControlAction::Check,
        },
        other => panic!("unexpected attached-required malformed case {other}"),
    };
    let err = dispatch_matrix_request(&ctx, request)
        .await
        .expect_err("detached request fails before worker delivery");
    assert_eq!(err.code, ErrorCode::NotAttached);
}

#[cfg(unix)]
async fn assert_steer_delegation_malformed() {
    let ctx = test_ctx();
    let response = dispatch_matrix_request(
        &ctx,
        Request::SteerDelegation {
            session_id: Uuid::new_v4(),
            task_call_id: "task-1".into(),
            label: "child".into(),
            message: "steer".into(),
        },
    )
    .await
    .expect("unknown steer target is typed non-applied response");
    let Response::DelegationSteer { result } = response else {
        panic!("expected DelegationSteer");
    };
    assert_eq!(result.status, proto::DelegationSteerStatus::NotSteerable);
}

#[cfg(unix)]
async fn assert_fs_mutating_malformed(kind: &str) {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let request = match kind {
        "fs_write" => Request::FsWrite {
            project_root: tmp.path().to_string_lossy().into_owned(),
            path: "../outside.txt".into(),
            content: "bad".into(),
            base_hash: None,
        },
        "fs_create_dir" => Request::FsCreateDir {
            project_root: tmp.path().to_string_lossy().into_owned(),
            path: "../outside".into(),
        },
        "fs_rename" => Request::FsRename {
            project_root: tmp.path().to_string_lossy().into_owned(),
            from_path: "../outside".into(),
            to_path: "new".into(),
        },
        "fs_delete" => Request::FsDelete {
            project_root: tmp.path().to_string_lossy().into_owned(),
            path: "../outside".into(),
        },
        _ => unreachable!(),
    };
    let err = dispatch_matrix_request(&ctx, request)
        .await
        .expect_err("fs traversal is rejected");
    assert_eq!(err.code, ErrorCode::PathOutsideRoot);
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[cfg(unix)]
async fn assert_attachment_mutating_happy(kind: &str) {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (session_id, _work_rx) = live_worker_with_receiver(&ctx, tmp.path());
    let png = sample_png();
    let sha = sha256_hex(&png);
    let data = base64::engine::general_purpose::STANDARD.encode(&png);
    let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
    let mut client = ProtoStream::new(client_stream);
    let server = tokio::spawn(handle_client_transport(server_stream, ctx.clone()));
    match recv_body(&mut client).await {
        Body::Response { id, response } => {
            assert_eq!(id, Uuid::nil());
            assert!(matches!(*response, Response::DaemonStatus { .. }));
        }
        other => panic!("expected daemon hello, got {other:?}"),
    }
    let attach_id = Uuid::new_v4();
    client
        .send(&Envelope::request(
            attach_id,
            attach_existing_request(session_id, tmp.path()),
        ))
        .await
        .expect("send attachment attach");
    recv_dispatch_matrix_response(&mut client, attach_id)
        .await
        .expect("attach for attachment upload");
    let begin_id = Uuid::new_v4();
    client
        .send(&Envelope::request(
            begin_id,
            Request::BeginAttachmentUpload {
                mime: proto::IMAGE_ATTACHMENT_MIME_PNG.into(),
                byte_len: png.len(),
                sha256: sha,
                purpose: proto::AttachmentPurpose::UserMessageImage,
            },
        ))
        .await
        .expect("send begin upload");
    let Response::AttachmentUploadStarted { upload_id, .. } =
        recv_dispatch_matrix_response(&mut client, begin_id)
            .await
            .expect("begin upload")
    else {
        panic!("expected AttachmentUploadStarted");
    };

    if kind == "begin_attachment_upload" {
        let chunk_id = Uuid::new_v4();
        client
            .send(&Envelope::request(
                chunk_id,
                Request::UploadAttachmentChunk {
                    upload_id,
                    offset: 0,
                    data_base64: data,
                },
            ))
            .await
            .expect("send chunk");
        assert!(matches!(
            recv_dispatch_matrix_response(&mut client, chunk_id)
                .await
                .expect("chunk after begin"),
            Response::AttachmentChunkAccepted { .. }
        ));
    } else if kind == "cancel_attachment_upload" {
        let cancel_id = Uuid::new_v4();
        client
            .send(&Envelope::request(
                cancel_id,
                Request::CancelAttachmentUpload { upload_id },
            ))
            .await
            .expect("send cancel");
        assert!(matches!(
            recv_dispatch_matrix_response(&mut client, cancel_id)
                .await
                .expect("cancel upload"),
            Response::Ack
        ));
        let finish_id = Uuid::new_v4();
        client
            .send(&Envelope::request(
                finish_id,
                Request::FinishAttachmentUpload { upload_id },
            ))
            .await
            .expect("send finish after cancel");
        let err = recv_dispatch_matrix_response(&mut client, finish_id)
            .await
            .expect_err("cancel removes pending upload");
        assert_eq!(err.code, ErrorCode::BadRequest);
    } else {
        let chunk_id = Uuid::new_v4();
        client
            .send(&Envelope::request(
                chunk_id,
                Request::UploadAttachmentChunk {
                    upload_id,
                    offset: 0,
                    data_base64: data,
                },
            ))
            .await
            .expect("send chunk");
        assert!(matches!(
            recv_dispatch_matrix_response(&mut client, chunk_id)
                .await
                .expect("chunk upload"),
            Response::AttachmentChunkAccepted { .. }
        ));
        let finish_id = Uuid::new_v4();
        client
            .send(&Envelope::request(
                finish_id,
                Request::FinishAttachmentUpload { upload_id },
            ))
            .await
            .expect("send finish");
        assert!(matches!(
            recv_dispatch_matrix_response(&mut client, finish_id)
                .await
                .expect("finish upload"),
            Response::AttachmentUploaded { .. }
        ));
    }
    drop(client);
    server
        .await
        .expect("server task joins")
        .expect("server task succeeds");
}

#[cfg(unix)]
async fn assert_attachment_mutating_malformed(kind: &str) {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (session_id, _work_rx) = live_worker_with_receiver(&ctx, tmp.path());
    let prelude = vec![attach_existing_request(session_id, tmp.path())];
    let err = match kind {
        "begin_attachment_upload" => dispatch_matrix_request_after(
            &ctx,
            prelude,
            Request::BeginAttachmentUpload {
                mime: "text/plain".into(),
                byte_len: 1,
                sha256: "0".repeat(64),
                purpose: proto::AttachmentPurpose::UserMessageImage,
            },
        )
        .await
        .expect_err("unsupported attachment mime"),
        "upload_attachment_chunk" => dispatch_matrix_request_after(
            &ctx,
            prelude,
            Request::UploadAttachmentChunk {
                upload_id: Uuid::new_v4(),
                offset: 0,
                data_base64: String::new(),
            },
        )
        .await
        .expect_err("unknown upload chunk"),
        "finish_attachment_upload" => dispatch_matrix_request_after(
            &ctx,
            prelude,
            Request::FinishAttachmentUpload {
                upload_id: Uuid::new_v4(),
            },
        )
        .await
        .expect_err("unknown upload finish"),
        "cancel_attachment_upload" => {
            let response = dispatch_matrix_request_after(
                &ctx,
                prelude,
                Request::CancelAttachmentUpload {
                    upload_id: Uuid::new_v4(),
                },
            )
            .await
            .expect("unknown upload cancel is typed idempotent ack");
            assert!(matches!(response, Response::Ack));
            return;
        }
        _ => unreachable!(),
    };
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[cfg(unix)]
async fn assert_terminal_mutating_happy(kind: &str) {
    let ctx = test_ctx();
    match kind {
        "open_terminal" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::OpenTerminal {
                    cwd: None,
                    cols: 80,
                    rows: 24,
                },
            )
            .await
            .expect("open terminal");
            let Response::TerminalOpened { terminal_id, .. } = response else {
                panic!("expected TerminalOpened");
            };
            let response = dispatch_matrix_request(&ctx, Request::CloseTerminal { terminal_id })
                .await
                .expect("close opened terminal");
            assert!(matches!(response, Response::Ack));
        }
        "close_terminal" => {
            let Response::TerminalOpened { terminal_id, .. } = dispatch_matrix_request(
                &ctx,
                Request::OpenTerminal {
                    cwd: None,
                    cols: 80,
                    rows: 24,
                },
            )
            .await
            .expect("open terminal") else {
                panic!("expected TerminalOpened");
            };
            let response = dispatch_matrix_request(&ctx, Request::CloseTerminal { terminal_id })
                .await
                .expect("close terminal");
            assert!(matches!(response, Response::Ack));
            let err = dispatch_matrix_request(
                &ctx,
                Request::AttachTerminal {
                    terminal_id,
                    cols: 80,
                    rows: 24,
                },
            )
            .await
            .expect_err("closed terminal is absent");
            assert_eq!(err.code, ErrorCode::BadRequest);
        }
        _ => unreachable!(),
    }
}

#[cfg(unix)]
async fn assert_terminal_mutating_malformed(kind: &str) {
    let ctx = test_ctx();
    let request = match kind {
        "open_terminal" => Request::OpenTerminal {
            cwd: Some("/definitely/missing/cockpit-terminal-cwd".into()),
            cols: 80,
            rows: 24,
        },
        "close_terminal" => Request::CloseTerminal {
            terminal_id: Uuid::new_v4(),
        },
        _ => unreachable!(),
    };
    let err = dispatch_matrix_request(&ctx, request)
        .await
        .expect_err("terminal invalid state rejected");
    assert!(matches!(
        err.code,
        ErrorCode::BadRequest | ErrorCode::RootMissing
    ));
}

#[cfg(unix)]
async fn assert_paused_work_mutating_happy(kind: &str) {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    ctx.db
        .upsert_paused_session_work(
            session.session_id,
            "Build",
            "/repo",
            "test pause",
            1,
            "test-version",
        )
        .unwrap();
    let request = match kind {
        "resume_paused_work" => Request::ResumePausedWork {
            session_id: session.session_id,
        },
        "cancel_paused_work" => Request::CancelPausedWork {
            session_id: session.session_id,
        },
        _ => unreachable!(),
    };
    let response = dispatch_matrix_request(&ctx, request)
        .await
        .expect("paused work mutation");
    assert!(matches!(response, Response::Ack));
    match kind {
        "resume_paused_work" | "cancel_paused_work" => assert!(
            ctx.db
                .paused_session_work(session.session_id)
                .unwrap()
                .is_none()
        ),
        _ => unreachable!(),
    }
}

#[cfg(unix)]
async fn assert_goal_mutating_happy(kind: &str) {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    ctx.db
        .create_session_goal(
            session.session_id,
            &session.project_id,
            "ship goal rpc",
            None,
            Some(100),
        )
        .unwrap();
    let response = dispatch_matrix_request(
        &ctx,
        match kind {
            "set_goal_status" => Request::SetGoalStatus {
                session_id: session.session_id,
                status: proto::GoalStatus::Paused,
            },
            "clear_goal" => Request::ClearGoal {
                session_id: session.session_id,
            },
            _ => unreachable!(),
        },
    )
    .await
    .expect("goal mutation");
    match (kind, response) {
        ("set_goal_status", Response::GoalUpdated { goal }) => {
            assert_eq!(goal.session_id, session.session_id);
            assert_eq!(goal.status, proto::GoalStatus::Paused);
        }
        ("clear_goal", Response::GoalCleared { cleared }) => {
            assert!(cleared);
            assert!(
                ctx.db
                    .current_session_goal(session.session_id, false)
                    .unwrap()
                    .is_none()
            );
        }
        _ => panic!("unexpected goal mutation response"),
    }
}

#[cfg(unix)]
async fn assert_goal_mutating_malformed(kind: &str) {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    match kind {
        "set_goal_status" => {
            let err = dispatch_matrix_request(
                &ctx,
                Request::SetGoalStatus {
                    session_id: session.session_id,
                    status: proto::GoalStatus::Paused,
                },
            )
            .await
            .expect_err("missing open goal rejects status change");
            assert_eq!(err.code, ErrorCode::BadRequest);
        }
        "clear_goal" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::ClearGoal {
                    session_id: session.session_id,
                },
            )
            .await
            .expect("missing open goal is a typed no-op");
            assert!(matches!(response, Response::GoalCleared { cleared: false }));
        }
        _ => unreachable!(),
    }
}

fn create_test_assistant(
    ctx: &Arc<DaemonContext>,
    tmp: &tempfile::TempDir,
    name: &str,
) -> crate::db::assistants::AssistantRow {
    crate::assistants::create_assistant(
        &ctx.db,
        crate::assistants::CreateAssistantSpec {
            name: name.to_string(),
            description: "test assistant".to_string(),
            mode: crate::agents::AgentMode::Primary,
            tools: None,
            tool_tiers: std::collections::BTreeMap::new(),
            model: None,
            prompt: "You are a test assistant.".to_string(),
            home_dir: tmp.path().join(name),
        },
    )
    .expect("create assistant")
}

#[cfg(unix)]
async fn assert_create_assistant_session_happy() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    create_test_assistant(&ctx, &tmp, "helper-bot");
    let response = dispatch_matrix_request(
        &ctx,
        Request::CreateAssistantSession {
            name: "helper-bot".into(),
            project_root: project.path().to_string_lossy().into_owned(),
            no_sandbox: false,
            env_snapshot: None,
        },
    )
    .await
    .expect("create assistant session");
    let Response::AssistantSessionCreated { session } = response else {
        panic!("expected AssistantSessionCreated");
    };
    assert_eq!(session.assistant_name, "helper-bot");
    assert_eq!(session.active_agent, "helper-bot");
    assert!(
        ctx.registry
            .active_session_ids()
            .contains(&session.session_id),
        "assistant session is started through the registry"
    );
    assert!(
        ctx.db.get_session(session.session_id).unwrap().is_none(),
        "assistant session remains deferred until first user message"
    );
}

#[cfg(unix)]
async fn assert_auto_title_mutating_happy() {
    let project = tempfile::tempdir().unwrap();
    let url = auto_title_model_server(Some("Matrix Title".to_string())).await;
    let ctx = test_ctx_with_config_source(auto_title_config_source(&url));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", project.path().to_str().unwrap(), "Build")
        .unwrap();
    let response = dispatch_matrix_request(
        &ctx,
        Request::AutoTitle {
            session_id: session.session_id,
        },
    )
    .await
    .expect("auto-title happy");
    let Response::AutoTitle { title, .. } = response else {
        panic!("expected AutoTitle");
    };
    assert_eq!(title, "matrix-title");
    assert_eq!(
        ctx.db
            .get_session(session.session_id)
            .unwrap()
            .unwrap()
            .title
            .as_deref(),
        Some("matrix-title")
    );
}

#[cfg(unix)]
async fn assert_auto_title_mutating_malformed() {
    let project = tempfile::tempdir().unwrap();
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
    ));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", project.path().to_str().unwrap(), "Build")
        .unwrap();
    let err = dispatch_matrix_request(
        &ctx,
        Request::AutoTitle {
            session_id: session.session_id,
        },
    )
    .await
    .expect_err("auto-title missing utility model rejects");
    assert_eq!(err.code, ErrorCode::BadRequest);
    let row = ctx.db.get_session(session.session_id).unwrap().unwrap();
    assert!(row.title.is_none());
    assert!(!row.user_renamed);
}

#[cfg(unix)]
async fn assert_curator_mutating_happy() {
    let project = tempfile::tempdir().unwrap();
    let skill_root = project.path().join(".agents").join("skills");
    write_curator_skill(&skill_root, "matrix-skill");
    let ctx = test_ctx_with_config_source(curator_config_source(&skill_root));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let response = dispatch_matrix_request(
        &ctx,
        Request::Curator {
            project_root: project.path().to_string_lossy().into_owned(),
            action: proto::CuratorAction::Pin {
                name: "matrix-skill".to_string(),
            },
        },
    )
    .await
    .expect("curator happy");
    assert!(matches!(
        response,
        Response::Curator {
            result: proto::CuratorResult::Pinned { pinned: true, .. }
        }
    ));
    assert!(
        ctx.db
            .get_skill_usage("matrix-skill")
            .unwrap()
            .expect("skill usage row")
            .pinned
    );
}

#[cfg(unix)]
async fn assert_session_db_mutating_happy(kind: &str) {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let session = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    match kind {
        "archive_session" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::ArchiveSession {
                    session_id: session.session_id,
                    cascade: false,
                },
            )
            .await
            .expect("archive session");
            assert!(matches!(response, Response::Ack));
            assert!(
                ctx.db
                    .get_session(session.session_id)
                    .unwrap()
                    .unwrap()
                    .archived_at
                    .is_some()
            );
        }
        "unarchive_session" => {
            ctx.db.archive_session(session.session_id, false).unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::UnarchiveSession {
                    session_id: session.session_id,
                },
            )
            .await
            .expect("unarchive session");
            assert!(matches!(response, Response::Ack));
            assert!(
                ctx.db
                    .get_session(session.session_id)
                    .unwrap()
                    .unwrap()
                    .archived_at
                    .is_none()
            );
        }
        "fork_session" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::ForkSession {
                    parent_session_id: session.session_id,
                    fork_point_turn_id: None,
                    ephemeral: false,
                },
            )
            .await
            .expect("fork session");
            let Response::Forked {
                session_id: fork_id,
                parent_session_id,
                ..
            } = response
            else {
                panic!("expected Forked");
            };
            assert_eq!(parent_session_id, session.session_id);
            assert_eq!(
                ctx.db
                    .get_session(fork_id)
                    .unwrap()
                    .unwrap()
                    .parent_session_id,
                Some(session.session_id)
            );
        }
        "discard_session" => {
            let fork = ctx
                .db
                .create_ephemeral_fork(session.session_id, None)
                .unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::DiscardSession {
                    session_id: fork.session_id,
                },
            )
            .await
            .expect("discard ephemeral session");
            assert!(matches!(response, Response::Ack));
            assert!(ctx.db.get_session(fork.session_id).unwrap().is_none());
        }
        "btw_create" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::CreateBtwFork {
                    parent_session_id: session.session_id,
                    tangent: false,
                },
            )
            .await
            .expect("create btw fork");
            let Response::BtwFork { info, created } = response else {
                panic!("expected BtwFork");
            };
            assert!(created);
            assert_eq!(info.parent_session_id, session.session_id);
            assert!(ctx.db.get_session(info.session_id).unwrap().is_some());
        }
        "btw_end" => {
            let fork = ctx.db.create_btw_fork(session.session_id, false).unwrap();
            let response = dispatch_matrix_request(
                &ctx,
                Request::EndBtwFork {
                    parent_session_id: session.session_id,
                },
            )
            .await
            .expect("end btw fork");
            assert!(matches!(response, Response::Ack));
            assert!(ctx.db.get_session(fork.info.session_id).unwrap().is_none());
        }
        "rename_session" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::RenameSession {
                    session_id: session.session_id,
                    title: "New title".into(),
                },
            )
            .await
            .expect("rename session");
            assert!(matches!(response, Response::Ack));
            assert_eq!(
                ctx.db
                    .get_session(session.session_id)
                    .unwrap()
                    .unwrap()
                    .title,
                Some("New title".into())
            );
        }
        "share_session" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::ShareSession {
                    session_id: session.session_id,
                    shared: true,
                },
            )
            .await
            .expect("share session");
            assert!(matches!(response, Response::Ack));
            assert!(
                ctx.db
                    .get_session(session.session_id)
                    .unwrap()
                    .unwrap()
                    .shared_with_collaborators
            );
        }
        "record_session_note" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::RecordSessionNote {
                    session_id: session.session_id,
                    text: "note".into(),
                },
            )
            .await
            .expect("record note");
            let Response::NoteRecorded { seq } = response else {
                panic!("expected NoteRecorded");
            };
            assert!(seq > 0);
            let events = ctx.db.list_session_events(session.session_id).unwrap();
            assert!(events.iter().any(|event| {
                event.kind == "user_note"
                    && event.data.get("text").and_then(|v| v.as_str()) == Some("note")
            }));
        }
        "delete_session" => {
            let response = dispatch_matrix_request(
                &ctx,
                Request::DeleteSession {
                    session_id: session.session_id,
                    cascade: false,
                },
            )
            .await
            .expect("delete session");
            assert!(matches!(response, Response::Ack));
            assert!(ctx.db.get_session(session.session_id).unwrap().is_none());
        }
        _ => unreachable!(),
    }
}

#[cfg(unix)]
async fn assert_session_db_mutating_malformed(kind: &str) {
    let ctx = test_ctx();
    let session = ctx.db.create_session("p", "/repo", "Build").unwrap();
    let missing = Uuid::new_v4();
    let request = match kind {
        "archive_session" => Request::ArchiveSession {
            session_id: missing,
            cascade: false,
        },
        "unarchive_session" => Request::UnarchiveSession {
            session_id: missing,
        },
        "fork_session" => Request::ForkSession {
            parent_session_id: missing,
            fork_point_turn_id: None,
            ephemeral: false,
        },
        "discard_session" => Request::DiscardSession {
            session_id: session.session_id,
        },
        "btw_create" => Request::CreateBtwFork {
            parent_session_id: missing,
            tangent: false,
        },
        "btw_end" => Request::EndBtwFork {
            parent_session_id: missing,
        },
        "rename_session" => Request::RenameSession {
            session_id: missing,
            title: "bad".into(),
        },
        "share_session" => Request::ShareSession {
            session_id: missing,
            shared: true,
        },
        "record_session_note" => Request::RecordSessionNote {
            session_id: missing,
            text: "bad".into(),
        },
        "delete_session" => Request::DeleteSession {
            session_id: missing,
            cascade: false,
        },
        _ => unreachable!(),
    };
    let result = dispatch_matrix_request(&ctx, request).await;
    match kind {
        // `btw_end` is an idempotent no-op on a parent with no live fork
        // (`Db::end_btw_fork` returns `Ok(false)`), same as discard/share.
        "discard_session" | "share_session" | "btw_end" => {
            assert!(matches!(
                result.expect("invalid state is typed no-op"),
                Response::Ack
            ));
        }
        _ => {
            let err = result.expect_err("invalid session mutation rejected");
            assert!(matches!(
                err.code,
                ErrorCode::BadRequest | ErrorCode::UnknownSession
            ));
        }
    }
    assert!(ctx.db.get_session(session.session_id).unwrap().is_some());
}

#[cfg(unix)]
async fn assert_promote_resource_happy() {
    let ctx = persistent_test_ctx();
    let scheduler = ctx
        .registry
        .resource_scheduler()
        .expect("persistent scheduler");
    let _running = scheduler
        .submit(
            crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
            ),
        )
        .expect("running ticket");
    let queued = scheduler
        .submit(
            crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
            ),
        )
        .expect("queued ticket");
    let response = dispatch_matrix_request(
        &ctx,
        Request::PromoteResource {
            request_id: queued.display_id().to_string(),
            session_id: None,
        },
    )
    .await
    .expect("promote resource");
    let Response::PromoteResourceResult { status, .. } = response else {
        panic!("expected PromoteResourceResult");
    };
    assert_eq!(status, proto::ResourcePromoteStatus::Promoted);
}

#[cfg(unix)]
async fn assert_scheduler_shared_only_dispatch(kind: &str) {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let request = authz_matrix_request(kind, Uuid::new_v4(), tmp.path());
    let err = dispatch_matrix_request(&ctx, request)
        .await
        .expect_err("scheduler RPCs are shared-daemon-only in the matrix context");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(
        err.message.contains("shared daemon"),
        "unexpected scheduler error: {}",
        err.message
    );
}

#[cfg(unix)]
async fn assert_scheduler_dispatch_happy(kind: &str) {
    let ctx = persistent_test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let scheduler = ctx.scheduler.as_ref().expect("persistent scheduler");
    if kind != "create_scheduled_job" {
        dispatch_matrix_request(
            &ctx,
            authz_matrix_request("create_scheduled_job", Uuid::new_v4(), tmp.path()),
        )
        .await
        .expect("seed scheduled job");
    }
    let response =
        dispatch_matrix_request(&ctx, authz_matrix_request(kind, Uuid::new_v4(), tmp.path()))
            .await
            .expect("scheduler happy path");
    match kind {
        "create_scheduled_job" => {
            assert!(matches!(response, Response::ScheduledJob { .. }));
            assert!(
                scheduler
                    .list_jobs(None)
                    .unwrap()
                    .iter()
                    .any(|job| job.id == "job-authz")
            );
        }
        "delete_scheduled_job" => {
            assert!(matches!(
                response,
                Response::ScheduledJobDeleted { deleted: true, .. }
            ));
            assert!(
                scheduler
                    .list_jobs(None)
                    .unwrap()
                    .iter()
                    .all(|job| job.id != "job-authz")
            );
        }
        "set_scheduled_job_enabled" => {
            let Response::ScheduledJob { job } = response else {
                panic!("expected scheduled job response");
            };
            assert!(job.enabled);
        }
        "run_scheduled_job" => {
            assert!(matches!(response, Response::ScheduledJobRunQueued { .. }));
        }
        other => panic!("unexpected scheduler dispatch kind {other}"),
    }
}

#[cfg(unix)]
async fn assert_in_memory_or_global_mutating_happy(kind: &str) {
    match kind {
        "set_approval_mode" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let (session_id, _work_rx) = live_worker_with_receiver(&ctx, tmp.path());
            let (response, events) = dispatch_matrix_request_after_collect_events(
                &ctx,
                vec![attach_existing_request(session_id, tmp.path())],
                Request::SetApprovalMode {
                    mode: crate::config::extended::ApprovalMode::Yolo,
                },
            )
            .await;
            let response = response.expect("set approval mode");
            let Response::ApprovalModeState { mode } = response else {
                panic!("expected ApprovalModeState");
            };
            assert_eq!(mode, crate::config::extended::ApprovalMode::Yolo);
            assert!(events.iter().any(|event| matches!(
                event,
                proto::Event::ApprovalModeState {
                    session_id: got,
                    mode: crate::config::extended::ApprovalMode::Yolo
                } if *got == session_id
            )));
        }
        "set_sandbox" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let (session_id, _work_rx) = live_worker_with_receiver(&ctx, tmp.path());
            let (response, events) = dispatch_matrix_request_after_collect_events(
                &ctx,
                vec![attach_existing_request(session_id, tmp.path())],
                Request::SetSandbox {
                    mode: Some(crate::tools::sandbox_mode::SandboxMode::Sandbox),
                    container_network_enabled: Some(false),
                },
            )
            .await;
            let response = response.expect("set sandbox");
            let Response::SandboxState { enabled, .. } = response else {
                panic!("expected SandboxState");
            };
            assert!(enabled);
            assert!(events.iter().any(|event| matches!(
                event,
                proto::Event::SandboxState {
                    session_id: got,
                    mode: crate::tools::sandbox_mode::SandboxMode::Sandbox,
                    enabled: true,
                    ..
                } if *got == session_id
            )));
        }
        "set_sandbox_escalation" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let (session_id, _work_rx) = live_worker_with_receiver(&ctx, tmp.path());
            let (response, events) = dispatch_matrix_request_after_collect_events(
                &ctx,
                vec![attach_existing_request(session_id, tmp.path())],
                Request::SetSandboxEscalation { enabled: false },
            )
            .await;
            let response = response.expect("set sandbox escalation");
            assert!(matches!(
                response,
                Response::SandboxEscalationState { enabled: false }
            ));
            assert!(events.iter().any(|event| matches!(
                event,
                proto::Event::SandboxEscalationState {
                    session_id: got,
                    enabled: false,
                } if *got == session_id
            )));
        }
        "set_caffeinate" => {
            let ctx = test_ctx();
            let (response, events) = dispatch_matrix_request_after_collect_events(
                &ctx,
                Vec::new(),
                Request::SetCaffeinate {
                    mode: crate::daemon::caffeinate::CaffeinateMode::On,
                },
            )
            .await;
            let response = response.expect("set caffeinate");
            let Response::CaffeinateState { active, .. } = response else {
                panic!("expected CaffeinateState");
            };
            assert!(events.iter().any(|event| matches!(
                event,
                proto::Event::CaffeinateState {
                    active: event_active,
                    ..
                } if *event_active == active
            )));
        }
        "refresh_env" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let (session_id, _work_rx) = live_worker_with_receiver(&ctx, tmp.path());
            let response = dispatch_matrix_request_after(
                &ctx,
                vec![attach_existing_request(session_id, tmp.path())],
                Request::RefreshEnv {
                    vars: HashMap::from([("COCKPIT_TEST_ENV".into(), "fresh".into())]),
                },
            )
            .await
            .expect("refresh env");
            assert!(matches!(response, Response::Ack));
            let handle = ctx.registry.live_handle(session_id).expect("live handle");
            assert_eq!(
                handle
                    .env_overlay()
                    .read()
                    .unwrap()
                    .get("COCKPIT_TEST_ENV")
                    .map(String::as_str),
                Some("fresh")
            );
        }
        "record_usage" => {
            let ctx = test_ctx();
            let response = dispatch_matrix_request(
                &ctx,
                Request::RecordUsage {
                    kind: proto::UsageKind::Slash,
                    key: "/help".into(),
                    project_id: None,
                },
            )
            .await
            .expect("record usage");
            assert!(matches!(response, Response::Ack));
            let counts = ctx.db.usage_counts("slash", None, 0).unwrap();
            assert_eq!(counts.get("/help"), Some(&1));
        }
        "store_flycockpit_credential" | "clear_flycockpit_credential" => {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("credential.json");
            let ctx = persistent_test_ctx_with_credential_path(path.clone());
            let response = dispatch_matrix_request(
                &ctx,
                Request::StoreFlycockpitCredential {
                    credential: flycockpit_credential(),
                },
            )
            .await
            .expect("store credential");
            assert!(matches!(response, Response::Ack));
            assert!(path.exists());
            if kind == "clear_flycockpit_credential" {
                let response = dispatch_matrix_request(&ctx, Request::ClearFlycockpitCredential)
                    .await
                    .expect("clear credential");
                assert!(matches!(response, Response::Ack));
                assert!(crate::auth::flycockpit::load_credential_from_path(path).is_err());
            }
        }
        "stop_daemon" => {
            let ctx = test_ctx();
            let response = dispatch_matrix_request(
                &ctx,
                Request::StopDaemon {
                    grace_secs: Some(2),
                },
            )
            .await
            .expect("stop daemon");
            assert!(matches!(response, Response::Ack));
            wait_for_shutdown_phase(&ctx, ShutdownPhase::Draining).await;
        }
        "lsp_control" => {
            let ctx = test_ctx();
            let tmp = tempfile::tempdir().unwrap();
            let (session_id, _work_rx) = live_worker_with_receiver(&ctx, tmp.path());
            let (response, events) = dispatch_matrix_request_after_collect_events(
                &ctx,
                vec![attach_existing_request(session_id, tmp.path())],
                Request::LspControl {
                    project_root: tmp.path().to_string_lossy().into_owned(),
                    server_id: "rust-analyzer".into(),
                    action: proto::LspControlAction::Check,
                },
            )
            .await;
            let response = response.expect("lsp control");
            let Response::LspControlResult { message } = response else {
                panic!("expected LspControlResult");
            };
            assert!(events.iter().any(|event| matches!(
                event,
                proto::Event::Notice { session_id: got, text }
                    if *got == session_id && *text == message
            )));
        }
        other => panic!("unexpected in-memory/global case {other}"),
    }
}

#[cfg(unix)]
fn attach_existing_request(session_id: Uuid, project_root: &Path) -> Request {
    Request::Attach {
        session_id: Some(session_id),
        since_seq: None,
        project_root: Some(project_root.to_string_lossy().into_owned()),
        no_sandbox: false,
        interactive: true,
        model_override: None,
        client_protocol_version: proto::PROTOCOL_VERSION,
        env_snapshot: None,
        env_policy: EnvDriftPolicy::Daemon,
    }
}

/// Criterion 4 (`engine-config-snapshot-adoption`): a client attached
/// through the real dispatch path receives the `ConfigSnapshot` event
/// without a separate request — the attach flow broadcasts it and the
/// event traverses the socket to the client.
#[cfg(unix)]
#[tokio::test]
async fn dispatch_attach_delivers_config_snapshot_event() {
    let project = tempfile::tempdir().unwrap();
    let mut providers = crate::config::providers::ProvidersConfig::default();
    providers.providers.insert(
        "p".to_string(),
        crate::config::providers::ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            ..crate::config::providers::ProviderEntry::default()
        },
    );
    providers.active_model = Some(crate::config::providers::ActiveModelRef {
        provider: "p".to_string(),
        model: "m".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
    });
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        providers,
        crate::config::extended::ExtendedConfig::default(),
    ));
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", project.path().to_str().unwrap(), "Build")
        .unwrap();
    let (result, events) = dispatch_matrix_request_after_collect_events(
        &ctx,
        vec![],
        attach_existing_request(session.session_id, project.path()),
    )
    .await;
    assert!(result.is_ok(), "attach through dispatch: {result:?}");
    assert!(
        events.iter().any(|event| matches!(
            event,
            proto::Event::ConfigSnapshot { snapshot }
                if snapshot.session_id == session.session_id
        )),
        "attach must deliver a ConfigSnapshot event over dispatch, got {events:?}"
    );
}

/// Criterion 6 (`engine-config-snapshot-adoption`): after a re-resolution
/// over a malformed layer, a dispatched client still holds the last good
/// snapshot (no new `ConfigSnapshot` event) and receives a `Notice`. Driven
/// through the real `RefreshConfig` dispatch path.
#[cfg(unix)]
#[tokio::test]
async fn dispatch_invalid_reresolve_keeps_last_good_snapshot() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let project = tempfile::tempdir().unwrap();
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let calls_for_load = calls.clone();
    let source = crate::daemon::config_source::ConfigSource::new(
        move |_cwd| {
            // First load (worker spawn) succeeds with a good snapshot; the
            // re-resolution triggered by RefreshConfig fails.
            if calls_for_load.fetch_add(1, Ordering::SeqCst) == 0 {
                let mut providers = crate::config::providers::ProvidersConfig::default();
                providers.providers.insert(
                    "p".to_string(),
                    crate::config::providers::ProviderEntry {
                        url: "http://localhost:1/v1".to_string(),
                        ..crate::config::providers::ProviderEntry::default()
                    },
                );
                providers.active_model = Some(crate::config::providers::ActiveModelRef {
                    provider: "p".to_string(),
                    model: "m".to_string(),
                    reasoning_effort: None,
                    thinking_mode: None,
                });
                Ok((
                    providers,
                    crate::config::extended::ExtendedConfig::default(),
                ))
            } else {
                Err(anyhow::anyhow!("malformed config layer"))
            }
        },
        |_cwd, _provider_id| None,
        |_cwd| crate::daemon::config_source::ConfigWatchPaths::default(),
    );
    let ctx = test_ctx_with_config_source(source);
    ctx.db
        .set_workspace_trust(
            project.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", project.path().to_str().unwrap(), "Build")
        .unwrap();
    let (result, events) = dispatch_matrix_request_after_collect_events(
        &ctx,
        vec![attach_existing_request(session.session_id, project.path())],
        Request::RefreshConfig,
    )
    .await;
    assert!(result.is_ok(), "refresh config dispatch: {result:?}");
    assert!(
        events.iter().any(|event| matches!(
            event,
            proto::Event::Notice { text, .. } if text.contains("last good snapshot")
        )),
        "invalid re-resolution must notify the client, got {events:?}"
    );
    // The only ConfigSnapshot delivered is the attach hydration at the last
    // good generation (0); the malformed re-resolution pushes no new one.
    assert!(
        !events.iter().any(|event| matches!(
            event,
            proto::Event::ConfigSnapshot { snapshot } if snapshot.generation >= 1
        )),
        "invalid re-resolution must not push a new-generation snapshot, got {events:?}"
    );
}

#[cfg(unix)]
fn git_repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    run_git(tmp.path(), &["init"]);
    tmp
}

#[cfg(unix)]
fn run_git(cwd: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

macro_rules! command_request_ordering_value {
    (serialized) => {
        principal::RequestOrdering::Serialized
    };
    (concurrent) => {
        principal::RequestOrdering::Concurrent
    };
}

macro_rules! request_ordering_rows_from_command_table {
    (($($context:ident),*) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
        vec![$(($kind, command_request_ordering_value!($ordering))),+]
    }};
}

#[test]
fn request_ordering_concurrent_set_is_exactly_the_twenty_one_enumerated_reads() {
    let rows = proto::command!(request_ordering_rows_from_command_table);
    assert!(
        rows.len() > 80,
        "command table should enumerate Request rows"
    );
    let actual: BTreeSet<_> = rows
        .iter()
        .filter_map(|(kind, ordering)| {
            (*ordering == principal::RequestOrdering::Concurrent).then_some(*kind)
        })
        .collect();
    let expected = BTreeSet::from([
        "daemon_status",
        "export_session_data",
        "fs_list",
        "fs_read",
        "fs_stat",
        "get_usage_counts",
        "git_diff_file",
        "git_status",
        "guidance_estimate",
        "list_agents",
        "list_assistants",
        "list_models",
        "list_scheduled_jobs",
        "list_sessions",
        "list_skills",
        "read_history_page",
        "read_session_messages",
        "resource_snapshot",
        "session_live_status",
        "stats_rollup",
        "subagent_transcript",
    ]);
    assert_eq!(actual, expected);
    for serialized in [
        "attach",
        "begin_attachment_upload",
        "upload_attachment_chunk",
        "finish_attachment_upload",
        "cancel_attachment_upload",
        "open_terminal",
        "attach_terminal",
        "terminal_input",
        "terminal_resize",
        "close_terminal",
        "send_user_message",
        "remove_queued_user_message",
        "remove_newest_queued_user_message",
        "remove_editable_queued_user_messages",
        "cancel_turn",
        "steer_delegation",
        "resolve_interrupt",
        "set_active_model",
        "set_agent",
        "set_llm_mode",
        "set_session_llm_mode",
        "set_approval_mode",
        "set_delegation_recursion",
        "set_sandbox",
        "set_sandbox_escalation",
        "set_preflight",
        "set_trusted_only",
        "set_redaction",
        "set_tandem_models",
    ] {
        let (_, ordering) = rows
            .iter()
            .find(|(kind, _)| *kind == serialized)
            .unwrap_or_else(|| panic!("missing request kind {serialized}"));
        assert_eq!(
            *ordering,
            principal::RequestOrdering::Serialized,
            "{serialized} must stay serialized"
        );
    }
}

#[test]
fn command_table_metadata_is_exhaustive_and_stable() {
    struct CommandMetadataCase {
        request: Request,
        kind: &'static str,
        session_id: Option<Uuid>,
        audit_path: Option<&'static str>,
        mutating: bool,
    }

    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (state, attached_session_id) = attached_state(&ctx, tmp.path());
    let attach_session_id = Uuid::from_u128(1);
    let transcript_session_id = Uuid::from_u128(2);
    let steer_session_id = Uuid::from_u128(3);
    let paused_session_id = Uuid::from_u128(4);
    let parent_session_id = Uuid::from_u128(5);
    let session_id = Uuid::from_u128(6);
    let promote_session_id = Uuid::from_u128(7);
    let upload_id = Uuid::from_u128(8);
    let terminal_id = Uuid::from_u128(9);
    let queue_item_id = Uuid::from_u128(10);
    let interrupt_id = Uuid::from_u128(11);
    let project_root = "/repo".to_string();

    let cases = vec![
        CommandMetadataCase {
            request: Request::Attach {
                session_id: Some(attach_session_id),
                since_seq: None,
                project_root: Some(project_root.clone()),
                no_sandbox: false,
                interactive: false,
                model_override: None,
                client_protocol_version: Default::default(),
                env_snapshot: None,
                env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
            },
            kind: "attach",
            session_id: Some(attach_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SubagentTranscript {
                session_id: transcript_session_id,
                task_call_id: "task-1".into(),
                label: "child".into(),
            },
            kind: "subagent_transcript",
            session_id: Some(transcript_session_id),
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::ReadSessionMessages {
                session_id: transcript_session_id,
                before_seq: None,
                limit: 20,
            },
            kind: "read_session_messages",
            session_id: Some(transcript_session_id),
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::ReadHistoryPage {
                session_id: transcript_session_id,
                before_seq: None,
                limit: 20,
            },
            kind: "read_history_page",
            session_id: Some(transcript_session_id),
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::SendUserMessage {
                text: "hello".into(),
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs: Vec::new(),
                forced_skill: None,
            },
            kind: "send_user_message",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SteerDelegation {
                session_id: steer_session_id,
                task_call_id: "task-1".into(),
                label: "child".into(),
                message: "go".into(),
            },
            kind: "steer_delegation",
            session_id: Some(steer_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::BeginAttachmentUpload {
                mime: "image/png".into(),
                byte_len: 1,
                sha256: "0".repeat(64),
                purpose: proto::AttachmentPurpose::UserMessageImage,
            },
            kind: "begin_attachment_upload",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::UploadAttachmentChunk {
                upload_id,
                offset: 0,
                data_base64: String::new(),
            },
            kind: "upload_attachment_chunk",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::FinishAttachmentUpload { upload_id },
            kind: "finish_attachment_upload",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::CancelAttachmentUpload { upload_id },
            kind: "cancel_attachment_upload",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RemoveQueuedUserMessage { queue_item_id },
            kind: "remove_queued_user_message",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RemoveNewestQueuedUserMessage {
                target_id: Some("root".into()),
            },
            kind: "remove_newest_queued_user_message",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RemoveEditableQueuedUserMessages {
                target_id: Some("root".into()),
            },
            kind: "remove_editable_queued_user_messages",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ResumePausedWork {
                session_id: paused_session_id,
            },
            kind: "resume_paused_work",
            session_id: Some(paused_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::CancelPausedWork {
                session_id: paused_session_id,
            },
            kind: "cancel_paused_work",
            session_id: Some(paused_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RepairResume {
                session_id: paused_session_id,
            },
            kind: "repair_resume",
            session_id: Some(paused_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::GoalStatus {
                session_id: attached_session_id,
            },
            kind: "goal_status",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::SetGoalStatus {
                session_id: attached_session_id,
                status: proto::GoalStatus::Paused,
            },
            kind: "set_goal_status",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ClearGoal {
                session_id: attached_session_id,
            },
            kind: "clear_goal",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ListAssistants,
            kind: "list_assistants",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::CreateAssistantSession {
                name: "helper-bot".into(),
                project_root: project_root.clone(),
                no_sandbox: false,
                env_snapshot: None,
            },
            kind: "create_assistant_session",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::AutoTitle {
                session_id: attached_session_id,
            },
            kind: "auto_title",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ExportSessionData {
                session_id: attached_session_id,
                kind: proto::ExportSessionKind::DebugBundle,
                include_generated_artifacts: false,
                include_sensitive: false,
            },
            kind: "export_session_data",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::Curator {
                project_root: project_root.clone(),
                action: proto::CuratorAction::Status,
            },
            kind: "curator",
            session_id: None,
            audit_path: Some("/repo"),
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::CancelTurn,
            kind: "cancel_turn",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::FsList {
                project_root: project_root.clone(),
                path: ".".into(),
                show_hidden: false,
            },
            kind: "fs_list",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::FsStat {
                project_root: project_root.clone(),
                path: "src/main.rs".into(),
            },
            kind: "fs_stat",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::FsRead {
                project_root: project_root.clone(),
                path: "src/main.rs".into(),
                base64: false,
            },
            kind: "fs_read",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::FsWrite {
                project_root: project_root.clone(),
                path: "src/main.rs".into(),
                content: "fn main() {}".into(),
                base_hash: None,
            },
            kind: "fs_write",
            session_id: None,
            audit_path: Some("src/main.rs"),
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::FsCreateDir {
                project_root: project_root.clone(),
                path: "src".into(),
            },
            kind: "fs_create_dir",
            session_id: None,
            audit_path: Some("src"),
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::FsRename {
                project_root: project_root.clone(),
                from_path: "old.rs".into(),
                to_path: "new.rs".into(),
            },
            kind: "fs_rename",
            session_id: None,
            audit_path: Some("old.rs -> new.rs"),
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::FsDelete {
                project_root: project_root.clone(),
                path: "old.rs".into(),
            },
            kind: "fs_delete",
            session_id: None,
            audit_path: Some("old.rs"),
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::GitStatus {
                project_root: project_root.clone(),
            },
            kind: "git_status",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::GitDiffFile {
                project_root: project_root.clone(),
                path: "src/main.rs".into(),
            },
            kind: "git_diff_file",
            session_id: None,
            audit_path: Some("src/main.rs"),
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::OpenTerminal {
                cwd: Some(project_root.clone()),
                cols: 80,
                rows: 24,
            },
            kind: "open_terminal",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::AttachTerminal {
                terminal_id,
                cols: 80,
                rows: 24,
            },
            kind: "attach_terminal",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::TerminalInput {
                terminal_id,
                bytes: b"pwd".to_vec(),
            },
            kind: "terminal_input",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::TerminalResize {
                terminal_id,
                cols: 100,
                rows: 40,
            },
            kind: "terminal_resize",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::CloseTerminal { terminal_id },
            kind: "close_terminal",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::LspControl {
                project_root: project_root.clone(),
                server_id: "rust-analyzer".into(),
                action: proto::LspControlAction::Check,
            },
            kind: "lsp_control",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ResolveInterrupt {
                interrupt_id,
                response: proto::ResolveResponse::Cancel,
            },
            kind: "resolve_interrupt",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ListSessions {
                project_id: Some("proj".into()),
                parent_session_id: None,
            },
            kind: "list_sessions",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::SessionLiveStatus {
                session_ids: vec![session_id],
            },
            kind: "session_live_status",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::ArchiveSession {
                session_id,
                cascade: false,
            },
            kind: "archive_session",
            session_id: Some(session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::UnarchiveSession { session_id },
            kind: "unarchive_session",
            session_id: Some(session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ForkSession {
                parent_session_id,
                fork_point_turn_id: None,
                ephemeral: false,
            },
            kind: "fork_session",
            session_id: Some(parent_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::DiscardSession { session_id },
            kind: "discard_session",
            session_id: Some(session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::CreateBtwFork {
                parent_session_id,
                tangent: false,
            },
            kind: "btw_create",
            session_id: Some(parent_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::EndBtwFork { parent_session_id },
            kind: "btw_end",
            session_id: Some(parent_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RenameSession {
                session_id,
                title: "new title".into(),
            },
            kind: "rename_session",
            session_id: Some(session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ShareSession {
                session_id,
                shared: true,
            },
            kind: "share_session",
            session_id: Some(session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RecordSessionNote {
                session_id,
                text: "note".into(),
            },
            kind: "record_session_note",
            session_id: Some(session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::DeleteSession {
                session_id,
                cascade: false,
            },
            kind: "delete_session",
            session_id: Some(session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ListSkills {
                project_root: project_root.clone(),
            },
            kind: "list_skills",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::ResourceSnapshot,
            kind: "resource_snapshot",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::PromoteResource {
                request_id: "rs-0001".into(),
                session_id: Some(promote_session_id),
            },
            kind: "promote_resource",
            session_id: Some(promote_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::CreateScheduledJob {
                job: proto::ScheduledJobCreate {
                    id: "job-1".into(),
                    owner: "system:test".into(),
                    schedule: proto::ScheduledJobSchedule::Every { seconds: 60 },
                    payload: proto::ScheduledJobPayload::Callback {
                        subsystem: "test".into(),
                    },
                    enabled: true,
                    missed_run_policy: proto::MissedRunPolicy::Skip,
                },
            },
            kind: "create_scheduled_job",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ListScheduledJobs { owner: None },
            kind: "list_scheduled_jobs",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::DeleteScheduledJob { id: "job-1".into() },
            kind: "delete_scheduled_job",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetScheduledJobEnabled {
                id: "job-1".into(),
                enabled: false,
            },
            kind: "set_scheduled_job_enabled",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RunScheduledJob { id: "job-1".into() },
            kind: "run_scheduled_job",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ListAgents,
            kind: "list_agents",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::ListModels {
                provider: Some("openai".into()),
            },
            kind: "list_models",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::SetActiveModel {
                provider: "openai".into(),
                model: "gpt".into(),
                trigger: proto::ActiveModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
            },
            kind: "set_active_model",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetAgent {
                name: "Build".into(),
            },
            kind: "set_agent",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetLlmMode {
                mode: Some(crate::config::extended::LlmMode::Normal),
            },
            kind: "set_llm_mode",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetSessionLlmMode {
                mode: crate::config::extended::LlmMode::Defensive,
            },
            kind: "set_session_llm_mode",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetApprovalMode {
                mode: crate::config::extended::ApprovalMode::Manual,
            },
            kind: "set_approval_mode",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetDelegationRecursion {
                enabled: true,
                default_depth: 2,
            },
            kind: "set_delegation_recursion",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetSandbox {
                mode: Some(crate::tools::sandbox_mode::SandboxMode::Sandbox),
                container_network_enabled: None,
            },
            kind: "set_sandbox",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetSandboxEscalation { enabled: false },
            kind: "set_sandbox_escalation",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetPreflight {
                enabled: Some(true),
            },
            kind: "set_preflight",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetTrustedOnly {
                enabled: Some(false),
            },
            kind: "set_trusted_only",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetRedaction {
                scan_environment: Some(true),
                scan_dotenv: None,
                scan_ssh_keys: None,
            },
            kind: "set_redaction",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetTandemModels {
                models: vec![(("openai".into()), ("gpt".into()))],
            },
            kind: "set_tandem_models",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::SetCaffeinate {
                mode: crate::daemon::caffeinate::CaffeinateMode::Toggle,
            },
            kind: "set_caffeinate",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::CancelSchedule {
                job_id: "job-1".into(),
            },
            kind: "cancel_schedule",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::Prune,
            kind: "prune",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::Compact,
            kind: "compact",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::Pin {
                text: "remember".into(),
            },
            kind: "pin",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::StoreFlycockpitCredential {
                credential: flycockpit_credential(),
            },
            kind: "store_flycockpit_credential",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::ClearFlycockpitCredential,
            kind: "clear_flycockpit_credential",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::DaemonStatus,
            kind: "daemon_status",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::RefreshEnv {
                vars: HashMap::from([("PATH".into(), "/bin".into())]),
            },
            kind: "refresh_env",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RefreshConfig,
            kind: "refresh_config",
            session_id: Some(attached_session_id),
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::RecordUsage {
                kind: proto::UsageKind::Slash,
                key: "/help".into(),
                project_id: None,
            },
            kind: "record_usage",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
        CommandMetadataCase {
            request: Request::GetUsageCounts {
                project_id: Some("proj".into()),
            },
            kind: "get_usage_counts",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::StatsRollup {
                project_id: Some("proj".into()),
                range: proto::StatsRange::Last7Days,
                by_role: true,
            },
            kind: "stats_rollup",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::GuidanceEstimate {
                project_root: project_root.clone(),
                provider: Some("openai".into()),
                model: Some("gpt".into()),
            },
            kind: "guidance_estimate",
            session_id: None,
            audit_path: None,
            mutating: false,
        },
        CommandMetadataCase {
            request: Request::StopDaemon { grace_secs: None },
            kind: "stop_daemon",
            session_id: None,
            audit_path: None,
            mutating: true,
        },
    ];

    // Drift-proof exhaustiveness (`daemon-trust-test-isolation.md`): the
    // single variant list below feeds both an exhaustive `match` with no
    // wildcard arm — so adding a `Request` variant without listing it
    // here is a *compile* error naming the uncovered variant — and the
    // expected-coverage set, so there is no hand-bumped count literal to
    // go stale.
    macro_rules! request_variants {
            ($($variant:ident),* $(,)?) => {
                fn request_variant_name(request: &Request) -> &'static str {
                    match request {
                        $(Request::$variant { .. } => stringify!($variant),)*
                    }
                }
                const REQUEST_VARIANT_NAMES: &[&str] = &[$(stringify!($variant)),*];
            };
        }
    request_variants!(
        Attach,
        SubagentTranscript,
        SendUserMessage,
        SteerDelegation,
        BeginAttachmentUpload,
        UploadAttachmentChunk,
        FinishAttachmentUpload,
        CancelAttachmentUpload,
        RemoveQueuedUserMessage,
        RemoveNewestQueuedUserMessage,
        RemoveEditableQueuedUserMessages,
        ResumePausedWork,
        CancelPausedWork,
        RepairResume,
        GoalStatus,
        SetGoalStatus,
        ClearGoal,
        ListAssistants,
        CreateAssistantSession,
        AutoTitle,
        ExportSessionData,
        Curator,
        CancelTurn,
        FsList,
        FsStat,
        FsRead,
        FsWrite,
        FsCreateDir,
        FsRename,
        FsDelete,
        GitStatus,
        GitDiffFile,
        OpenTerminal,
        AttachTerminal,
        TerminalInput,
        TerminalResize,
        CloseTerminal,
        LspControl,
        ResolveInterrupt,
        ListSessions,
        ReadSessionMessages,
        ReadHistoryPage,
        SessionLiveStatus,
        ArchiveSession,
        UnarchiveSession,
        ForkSession,
        DiscardSession,
        CreateBtwFork,
        EndBtwFork,
        RenameSession,
        ShareSession,
        RecordSessionNote,
        DeleteSession,
        ListSkills,
        ResourceSnapshot,
        PromoteResource,
        CreateScheduledJob,
        ListScheduledJobs,
        DeleteScheduledJob,
        SetScheduledJobEnabled,
        RunScheduledJob,
        ListAgents,
        ListModels,
        SetActiveModel,
        SetAgent,
        SetLlmMode,
        SetSessionLlmMode,
        SetApprovalMode,
        SetDelegationRecursion,
        SetSandbox,
        SetSandboxEscalation,
        SetPreflight,
        SetTrustedOnly,
        SetRedaction,
        SetTandemModels,
        SetCaffeinate,
        CancelSchedule,
        Prune,
        Compact,
        Pin,
        StoreFlycockpitCredential,
        ClearFlycockpitCredential,
        DaemonStatus,
        RefreshEnv,
        RefreshConfig,
        RecordUsage,
        GetUsageCounts,
        StatsRollup,
        GuidanceEstimate,
        StopDaemon,
    );

    let covered: HashSet<&'static str> = cases
        .iter()
        .map(|case| request_variant_name(&case.request))
        .collect();
    for variant in REQUEST_VARIANT_NAMES {
        assert!(
            covered.contains(variant),
            "Request::{variant} has no CommandMetadataCase — add one to this test"
        );
    }
    assert_eq!(
        cases.len(),
        REQUEST_VARIANT_NAMES.len(),
        "every Request variant has exactly one metadata case"
    );
    let mut kinds = HashSet::new();
    for case in cases {
        assert_eq!(principal::request_kind(&case.request), case.kind);
        assert!(
            kinds.insert(case.kind),
            "duplicate request kind {}",
            case.kind
        );
        assert_eq!(
            request_session_id(&case.request, &state),
            case.session_id,
            "{} session id",
            case.kind
        );
        assert_eq!(
            request_audit_path(&case.request).as_deref(),
            case.audit_path,
            "{} audit path",
            case.kind
        );
        assert_eq!(
            is_remote_mutating_request(&case.request),
            case.mutating,
            "{} mutating",
            case.kind
        );
    }
}

fn overlay_value(state: &MutableClientState, key: &str) -> Option<String> {
    state
        .attached
        .as_ref()
        .unwrap()
        .handle
        .env_overlay()
        .read()
        .unwrap()
        .get(key)
        .cloned()
}

fn sample_png() -> Vec<u8> {
    let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([1, 2, 3, 255]),
    ));
    let mut out = Vec::new();
    image
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

fn begin_upload_for(state: &mut MutableClientState, png: &[u8]) -> Uuid {
    match begin_attachment_upload(
        state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(png),
        proto::AttachmentPurpose::UserMessageImage,
    )
    .unwrap()
    {
        Response::AttachmentUploadStarted { upload_id, .. } => upload_id,
        other => panic!("unexpected response: {other:?}"),
    }
}

fn finish_attachment_upload_for_test(
    state: &mut MutableClientState,
    upload_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(finish_attachment_upload(state, upload_id))
}

fn finish_upload_for(state: &mut MutableClientState, png: &[u8]) -> proto::ImageAttachmentRef {
    let upload_id = begin_upload_for(state, png);
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(png);
    upload_attachment_chunk(state, upload_id, 0, data_base64).unwrap();
    match finish_attachment_upload_for_test(state, upload_id).unwrap() {
        Response::AttachmentUploaded { image_ref } => image_ref,
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn attachment_upload_consumes_image_refs_exactly_once() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, session_id) = attached_state(&ctx, tmp.path());
    let png = sample_png();
    let image_ref = finish_upload_for(&mut state, &png);

    let images = consume_image_refs(&mut state, session_id, std::slice::from_ref(&image_ref))
        .expect("first consume");
    assert_eq!(images, vec![png]);

    let err = consume_image_refs(&mut state, session_id, &[image_ref])
        .expect_err("second consume must fail");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("already consumed"));
}

#[test]
fn duplicate_image_refs_are_rejected_without_consuming() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, session_id) = attached_state(&ctx, tmp.path());
    let png = sample_png();
    let image_ref = finish_upload_for(&mut state, &png);

    let err = consume_image_refs(
        &mut state,
        session_id,
        &[image_ref.clone(), image_ref.clone()],
    )
    .expect_err("duplicate refs must fail");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("duplicate image ref"));

    let images = consume_image_refs(&mut state, session_id, &[image_ref]).unwrap();
    assert_eq!(images, vec![png]);
}

#[test]
fn attachment_ref_is_scoped_to_attached_session() {
    let ctx = test_ctx();
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let (mut state, session_a) = attached_state(&ctx, tmp_a.path());
    let (_, session_b) = attached_state(&ctx, tmp_b.path());
    let image_ref = finish_upload_for(&mut state, &sample_png());

    let err = consume_image_refs(&mut state, session_b, std::slice::from_ref(&image_ref))
        .expect_err("wrong session must fail");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("different session"));

    let images = consume_image_refs(&mut state, session_a, &[image_ref]).expect("owner consume");
    assert_eq!(images, vec![sample_png()]);
    assert_ne!(session_a, session_b);
}

#[test]
fn attachment_upload_rejects_bad_chunk_shapes() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    let png = sample_png();
    let upload_id = begin_upload_for(&mut state, &png);

    let err = upload_attachment_chunk(&mut state, upload_id, 1, "AAAA".to_string())
        .expect_err("offset mismatch");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("offset mismatch"));

    let err = upload_attachment_chunk(&mut state, upload_id, 0, "not base64!".to_string())
        .expect_err("invalid base64");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("valid base64"));
}

#[test]
fn attachment_finish_rejects_sha_mismatch_and_invalid_png() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    let png = sample_png();
    let upload_id = match begin_attachment_upload(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        "0".repeat(64),
        proto::AttachmentPurpose::UserMessageImage,
    )
    .unwrap()
    {
        Response::AttachmentUploadStarted { upload_id, .. } => upload_id,
        other => panic!("unexpected response: {other:?}"),
    };
    upload_attachment_chunk(
        &mut state,
        upload_id,
        0,
        base64::engine::general_purpose::STANDARD.encode(&png),
    )
    .unwrap();
    let err = finish_attachment_upload_for_test(&mut state, upload_id).expect_err("hash mismatch");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("SHA-256 mismatch"));

    let bad_png = b"not actually png".to_vec();
    let upload_id = begin_upload_for(&mut state, &bad_png);
    upload_attachment_chunk(
        &mut state,
        upload_id,
        0,
        base64::engine::general_purpose::STANDARD.encode(&bad_png),
    )
    .unwrap();
    let err = finish_attachment_upload_for_test(&mut state, upload_id).expect_err("invalid png");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("valid PNG"));
}

#[test]
fn png_validation_uses_strict_limits() {
    let large = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        proto::MAX_IMAGE_DIMENSION_PIXELS + 1,
        1,
        image::Rgba([1, 2, 3, 255]),
    ));
    let mut png = Vec::new();
    large
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();

    let err = validate_png_attachment_blocking(png).expect_err("dimension limit");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("decode limit"));
}

#[test]
fn attachment_upload_default_limits_match_config_defaults() {
    let limits = AttachmentUploadLimits::default();
    assert_eq!(limits.per_client_uploads, 4);
    assert_eq!(limits.global_uploads, 32);
    assert_eq!(limits.per_upload_bytes, proto::MAX_SINGLE_IMAGE_BYTES);
    assert_eq!(limits.global_bytes, 256 * 1024 * 1024);

    let cfg_limits: AttachmentUploadLimits = ExtendedConfig::default().daemon.uploads.into();
    assert_eq!(cfg_limits.per_client_uploads, limits.per_client_uploads);
    assert_eq!(cfg_limits.global_uploads, limits.global_uploads);
    assert_eq!(cfg_limits.per_upload_bytes, limits.per_upload_bytes);
    assert_eq!(cfg_limits.global_bytes, limits.global_bytes);
}

#[test]
fn attachment_upload_config_clamps_to_protocol_cap_and_warns() {
    let (limits, warning) =
        AttachmentUploadLimits::from_config_with_warning(DaemonUploadLimitsConfig {
            per_upload_bytes: 64 * 1024 * 1024,
            ..DaemonUploadLimitsConfig::default()
        });
    assert_eq!(limits.per_upload_bytes, proto::MAX_SINGLE_IMAGE_BYTES);
    assert_eq!(
        warning.as_deref(),
        Some("per_upload_bytes 64 MiB exceeds protocol cap 4 MiB; clamping")
    );

    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    let byte_len = proto::MAX_SINGLE_IMAGE_BYTES + 1;
    let err = begin_attachment_upload_with_limits(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        byte_len,
        "0".repeat(64),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .expect_err("upload above protocol cap is rejected by clamped per-upload limit");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(
        err.message.contains("pending-upload limit"),
        "{}",
        err.message
    );
}

#[test]
fn attachment_upload_config_below_protocol_cap_binds() {
    let configured = MIN_ATTACHMENT_UPLOAD_BYTES + 1;
    let (limits, warning) =
        AttachmentUploadLimits::from_config_with_warning(DaemonUploadLimitsConfig {
            per_upload_bytes: configured,
            ..DaemonUploadLimitsConfig::default()
        });
    assert_eq!(limits.per_upload_bytes, configured);
    assert!(warning.is_none());

    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    let err = begin_attachment_upload_with_limits(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        configured + 1,
        "0".repeat(64),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .expect_err("upload above configured cap is rejected even below protocol cap");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(
        err.message.contains("pending-upload limit"),
        "{}",
        err.message
    );
}

#[test]
fn attachment_upload_config_degenerate_per_upload_bytes_clamps_to_floor() {
    let (limits, warning) =
        AttachmentUploadLimits::from_config_with_warning(DaemonUploadLimitsConfig {
            per_upload_bytes: 0,
            ..DaemonUploadLimitsConfig::default()
        });
    assert_eq!(limits.per_upload_bytes, MIN_ATTACHMENT_UPLOAD_BYTES);
    assert_eq!(
        warning.as_deref(),
        Some("per_upload_bytes 0 bytes is below minimum 64 KiB; clamping")
    );
}

#[test]
fn attachment_upload_default_limits_enforce_per_client_count() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    let png = sample_png();

    for _ in 0..4 {
        begin_attachment_upload(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
        )
        .unwrap();
    }

    let err = begin_attachment_upload(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
    )
    .expect_err("fifth pending upload exceeds default per-client cap");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("limit 4"), "{}", err.message);
}

#[test]
fn attachment_upload_default_limits_enforce_global_count() {
    let ctx = test_ctx();
    let accounting = Arc::new(StdMutex::new(UploadAccounting::default()));
    let png = sample_png();
    let mut tempdirs = Vec::new();
    let mut states = Vec::new();

    for _ in 0..32 {
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        state.upload_accounting = accounting.clone();
        begin_attachment_upload(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
        )
        .unwrap();
        tempdirs.push(tmp);
        states.push(state);
    }

    let tmp = tempfile::tempdir().unwrap();
    let (mut overflow, _) = attached_state(&ctx, tmp.path());
    overflow.upload_accounting = accounting;
    let err = begin_attachment_upload(
        &mut overflow,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
    )
    .expect_err("thirty-third pending upload exceeds default daemon cap");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("limit 32"), "{}", err.message);
    drop((states, tempdirs, tmp));
}

#[test]
fn attachment_upload_limits_enforce_per_client_count_and_per_upload_bytes() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    let png = sample_png();
    let limits = AttachmentUploadLimits {
        per_client_uploads: 2,
        global_uploads: 32,
        per_upload_bytes: png.len(),
        global_bytes: usize::MAX,
    };

    begin_attachment_upload_with_limits(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .unwrap();
    begin_attachment_upload_with_limits(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .unwrap();
    let err = begin_attachment_upload_with_limits(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .expect_err("third pending upload exceeds per-client cap");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("this client"), "{}", err.message);

    let (mut state, _) = attached_state(&ctx, tmp.path());
    let err = begin_attachment_upload_with_limits(
        &mut state,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
        AttachmentUploadLimits {
            per_upload_bytes: png.len() - 1,
            ..limits
        },
    )
    .expect_err("declared upload exceeds per-upload cap");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(
        err.message.contains("pending-upload limit"),
        "{}",
        err.message
    );
}

#[test]
fn attachment_upload_limits_enforce_global_count_and_bytes() {
    let ctx = test_ctx();
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let (mut a, _) = attached_state(&ctx, tmp_a.path());
    let (mut b, _) = attached_state(&ctx, tmp_b.path());
    b.upload_accounting = a.upload_accounting.clone();
    let png = sample_png();
    let limits = AttachmentUploadLimits {
        per_client_uploads: 4,
        global_uploads: 1,
        per_upload_bytes: png.len(),
        global_bytes: usize::MAX,
    };

    let upload_id = begin_upload_for(&mut a, &png);
    let err = begin_attachment_upload_with_limits(
        &mut b,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .expect_err("second client exceeds daemon-global count cap");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("daemon has"), "{}", err.message);

    assert!(a.pending_uploads.remove(&upload_id).is_some());
    release_uploads(&a.upload_accounting, [upload_id]);
    let limits = AttachmentUploadLimits {
        global_uploads: 32,
        global_bytes: png.len(),
        ..limits
    };
    begin_attachment_upload_with_limits(
        &mut a,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .unwrap();
    let err = begin_attachment_upload_with_limits(
        &mut b,
        proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
        png.len(),
        sha256_hex(&png),
        proto::AttachmentPurpose::UserMessageImage,
        limits,
    )
    .expect_err("second client exceeds daemon-global byte cap");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("byte limit"), "{}", err.message);
}

#[test]
fn expired_pending_upload_prune_releases_global_accounting() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    let png = sample_png();
    let upload_id = begin_upload_for(&mut state, &png);
    state
        .pending_uploads
        .get_mut(&upload_id)
        .unwrap()
        .created_at = Instant::now() - Duration::from_secs(proto::PENDING_ATTACHMENT_TTL_SECS + 1);

    prune_expired_attachments(&mut state);

    assert!(state.pending_uploads.is_empty());
    assert!(
        crate::sync::lock_or_recover(&state.upload_accounting)
            .pending
            .is_empty()
    );
}

async fn recv_body<S>(proto: &mut ProtoStream<S>) -> Body
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match proto.recv().await.unwrap().unwrap() {
        RecvFrame::Envelope(env) => env.body,
        other => panic!("expected envelope, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_env_compat_accepts_path_snapshot() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let mut vars = HashMap::new();
    vars.insert("OPENAI_API_KEY".to_string(), "sk-new".to_string());
    vars.insert(
        "PATH".to_string(),
        "/home/me/.nvm/versions/node/v20/bin".to_string(),
    );
    handle_request(Request::RefreshEnv { vars }, &mut state, &ctx)
        .await
        .expect("PATH is accepted for compatibility");
    assert_eq!(
        overlay_value(&state, "OPENAI_API_KEY").as_deref(),
        Some("sk-new")
    );
    assert_eq!(
        overlay_value(&state, "PATH").as_deref(),
        Some("/home/me/.nvm/versions/node/v20/bin")
    );
}

#[tokio::test]
async fn refresh_env_is_scoped_to_attached_session_overlay() {
    let ctx = test_ctx();
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let (mut state_a, _) = attached_state(&ctx, tmp_a.path());
    let (mut state_b, _) = attached_state(&ctx, tmp_b.path());

    handle_request(
        Request::RefreshEnv {
            vars: HashMap::from([("OPENAI_API_KEY".to_string(), "sk-a".to_string())]),
        },
        &mut state_a,
        &ctx,
    )
    .await
    .expect("refresh a");
    handle_request(
        Request::RefreshEnv {
            vars: HashMap::from([("OPENAI_API_KEY".to_string(), "sk-b".to_string())]),
        },
        &mut state_b,
        &ctx,
    )
    .await
    .expect("refresh b");

    assert_eq!(
        overlay_value(&state_a, "OPENAI_API_KEY").as_deref(),
        Some("sk-a")
    );
    assert_eq!(
        overlay_value(&state_b, "OPENAI_API_KEY").as_deref(),
        Some("sk-b")
    );
}

#[test]
fn env_policy_daemon_keeps_baseline_and_reports_safe_drift() {
    let ctx = test_ctx();
    let baseline = EnvSnapshot::new(
        EnvSnapshotSource::DaemonStart,
        HashMap::from([
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("OPENAI_API_KEY".to_string(), "daemon-secret".to_string()),
        ]),
    );
    *ctx.env_baseline.write().unwrap() = baseline.clone();
    let client = EnvSnapshot::new(
        EnvSnapshotSource::TuiShell,
        HashMap::from([
            (
                "PATH".to_string(),
                "/usr/bin:/home/me/.nvm/versions/node/v20/bin".to_string(),
            ),
            ("OPENAI_API_KEY".to_string(), "client-secret".to_string()),
        ]),
    );

    let (chosen, baseline_meta, session_meta, drift, applied) =
        select_session_env(&ctx, Some(client), EnvDriftPolicy::Daemon).unwrap();

    assert_eq!(chosen.digest(), baseline.digest());
    assert_eq!(baseline_meta.digest, baseline.digest());
    assert_eq!(session_meta.digest, baseline.digest());
    assert_eq!(applied, EnvDriftPolicy::Daemon);
    let drift = drift.expect("drift summarized");
    assert_eq!(drift.changed_secret_keys, vec!["OPENAI_API_KEY"]);
    let serialized = serde_json::to_string(&drift).unwrap();
    assert!(!serialized.contains("client-secret"));
    assert!(!serialized.contains("daemon-secret"));
}

#[test]
fn env_policy_update_daemon_replaces_future_baseline() {
    let ctx = test_ctx();
    *ctx.env_baseline.write().unwrap() = EnvSnapshot::new(
        EnvSnapshotSource::DaemonStart,
        HashMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
    );
    let client = EnvSnapshot::new(
        EnvSnapshotSource::TuiShell,
        HashMap::from([("PATH".to_string(), "/opt/node/bin".to_string())]),
    );

    let (chosen, baseline_meta, session_meta, _, applied) =
        select_session_env(&ctx, Some(client.clone()), EnvDriftPolicy::UpdateDaemon).unwrap();

    assert_eq!(chosen.digest(), client.digest());
    assert_eq!(baseline_meta.digest, client.digest());
    assert_eq!(session_meta.digest, client.digest());
    assert_eq!(applied, EnvDriftPolicy::UpdateDaemon);
    assert_eq!(ctx.env_baseline.read().unwrap().digest(), client.digest());
}

#[test]
fn env_policy_error_on_drift_rejects() {
    let ctx = test_ctx();
    *ctx.env_baseline.write().unwrap() = EnvSnapshot::new(
        EnvSnapshotSource::DaemonStart,
        HashMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
    );
    let client = EnvSnapshot::new(
        EnvSnapshotSource::ExplicitCli,
        HashMap::from([("PATH".to_string(), "/custom/bin".to_string())]),
    );

    let err = select_session_env(&ctx, Some(client), EnvDriftPolicy::ErrorOnDrift)
        .expect_err("drift rejected");

    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("environment differs"));
}

#[cfg(unix)]
#[tokio::test]
async fn peer_uid_accepts_same_uid_socket_pair() {
    let (left, _right) = UnixStream::pair().expect("socket pair");

    validate_peer_owner(&left).expect("same uid peer is accepted");
    assert_eq!(peer_uid(&left).expect("peer uid"), current_uid());
}

#[cfg(unix)]
#[test]
fn peer_uid_rejects_mismatched_uid() {
    let daemon_uid = current_uid();
    let peer_uid = daemon_uid.saturating_add(1);

    let err = validate_peer_uid(peer_uid, daemon_uid).expect_err("different uid is rejected");

    let message = format!("{err:#}");
    assert!(message.contains(&format!("peer uid `{peer_uid}`")));
    assert!(message.contains(&format!("daemon uid `{daemon_uid}`")));
}

fn insert_hung_worker(ctx: &Arc<DaemonContext>, session_id: Uuid) {
    let session = Arc::new(
        Session::resume(ctx.db.clone(), session_id)
            .unwrap()
            .expect("session row"),
    );
    let locks = Arc::new(LockManager::from_db(ctx.db.clone()).expect("locks"));
    let handle = SessionWorkerHandle::test_handle(session, locks);
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);
}

#[tokio::test]
async fn set_agent_rejects_experimental_primary_when_mode_off() {
    let ctx = test_ctx();
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut state, session_id) = attached_state(&ctx, tmp.path());

    let err = handle_request(
        Request::SetAgent {
            name: "Swarm".into(),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("Swarm is gated when experimental mode is off");

    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("agent `Swarm`"));
    assert!(err.message.contains("requires experimental mode"));
    let got = ctx.db.get_session(session_id).unwrap().unwrap();
    assert_eq!(got.active_agent, "Build");
}

#[tokio::test]
async fn set_approval_mode_updates_session_and_broadcasts() {
    let ctx = test_ctx();
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut state, _session_id) = attached_state(&ctx, tmp.path());
    let mut event_rx = state
        .attached
        .as_ref()
        .expect("attached session")
        .handle
        .subscribe();

    let response = handle_request(
        Request::SetApprovalMode {
            mode: crate::config::extended::ApprovalMode::Yolo,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("approval mode request succeeds");
    match response {
        Response::ApprovalModeState { mode } => {
            assert_eq!(mode, crate::config::extended::ApprovalMode::Yolo);
        }
        other => panic!("expected ApprovalModeState response, got {other:?}"),
    }

    match event_rx.try_recv().expect("approval broadcast").event {
        proto::Event::ApprovalModeState { mode, .. } => {
            assert_eq!(mode, crate::config::extended::ApprovalMode::Yolo);
        }
        other => panic!("expected ApprovalModeState, got {other:?}"),
    }
}

#[tokio::test]
async fn set_sandbox_escalation_updates_session_and_broadcasts() {
    let ctx = test_ctx();
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut state, _session_id) = attached_state(&ctx, tmp.path());
    let mut event_rx = state
        .attached
        .as_ref()
        .expect("attached session")
        .handle
        .subscribe();

    let response = handle_request(
        Request::SetSandboxEscalation { enabled: false },
        &mut state,
        &ctx,
    )
    .await
    .expect("sandbox escalation request succeeds");
    match response {
        Response::SandboxEscalationState { enabled } => assert!(!enabled),
        other => panic!("expected SandboxEscalationState response, got {other:?}"),
    }

    let attached = state.attached.as_mut().expect("attached session");
    assert!(!attached.handle.sandbox_escalation_enabled());
    match event_rx
        .try_recv()
        .expect("sandbox escalation broadcast")
        .event
    {
        proto::Event::SandboxEscalationState { enabled, .. } => assert!(!enabled),
        other => panic!("expected SandboxEscalationState, got {other:?}"),
    }

    handle_request(
        Request::SetSandboxEscalation { enabled: false },
        &mut state,
        &ctx,
    )
    .await
    .expect("idempotent sandbox escalation request succeeds");
    assert!(
        event_rx.try_recv().is_err(),
        "idempotent set should not broadcast"
    );
}

#[tokio::test]
async fn set_agent_rejects_non_ownable_subagent_name() {
    let ctx = test_ctx();
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut state, session_id) = attached_state(&ctx, tmp.path());

    let err = handle_request(Request::SetAgent { name: "bee".into() }, &mut state, &ctx)
        .await
        .expect_err("subagent names are not root primaries");

    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("agent `bee`"));
    assert!(err.message.contains("not a chat-ownable primary"));
    let got = ctx.db.get_session(session_id).unwrap().unwrap();
    assert_eq!(got.active_agent, "Build");
}

#[test]
fn set_agent_allows_swarm_when_experimental_mode_on() {
    let ownable = vec![
        "Auto".to_string(),
        "Plan".to_string(),
        "Build".to_string(),
        "Swarm".to_string(),
        "Build".to_string(),
    ];

    validate_set_agent_name("Swarm", true, &ownable)
        .expect("Swarm is allowed when experimental mode is enabled");
}

#[test]
fn plan_default_available_everywhere_when_experimental_off_daemon_set_agent() {
    let ownable = vec!["Plan".to_string(), "Build".to_string()];

    validate_set_agent_name("Plan", false, &ownable)
        .expect("Plan is allowed when experimental mode is disabled");
    let err = validate_set_agent_name("Auto", false, &ownable)
        .expect_err("Auto remains gated when experimental mode is disabled");
    assert!(err.message.contains("requires experimental mode"));
    let err = validate_set_agent_name("Swarm", false, &ownable)
        .expect_err("Swarm remains gated when experimental mode is disabled");
    assert!(err.message.contains("requires experimental mode"));
}

#[test]
fn set_agent_allows_build_when_experimental_mode_off() {
    let ownable = vec!["Build".to_string()];

    validate_set_agent_name("Build", false, &ownable)
        .expect("Build remains a chat-ownable primary without experimental mode");
}

#[tokio::test]
async fn list_agents_returns_chat_ownable_primaries() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let response = handle_request(Request::ListAgents, &mut state, &ctx)
        .await
        .expect("list agents is implemented");
    let Response::Agents { agents } = response else {
        panic!("expected agents response");
    };

    assert_eq!(
        agents
            .iter()
            .map(|agent| agent.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Plan", "Build"]
    );
    for agent in &agents {
        assert!(agent.builtin);
        assert_eq!(agent.mode, "primary");
    }
}

#[tokio::test]
async fn list_agents_agrees_with_validate_set_agent() {
    let extended = crate::config::extended::ExtendedConfig {
        experimental_mode: true,
        ..Default::default()
    };
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        crate::config::providers::ProvidersConfig::default(),
        extended,
    ));
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let response = handle_request(Request::ListAgents, &mut state, &ctx)
        .await
        .expect("list agents succeeds");
    let Response::Agents { agents } = response else {
        panic!("expected agents response");
    };

    for agent in &agents {
        validate_set_agent(
            &ctx,
            state.attached.as_ref().expect("attached"),
            &agent.name,
        )
        .expect("listed agent is accepted by SetAgent validation");
    }
    let omitted = ["builder", "explore", "bee", "Multireview"];
    for name in omitted {
        assert!(
            !agents.iter().any(|agent| agent.name == name),
            "{name} must not be listed as chat-ownable"
        );
        validate_set_agent(&ctx, state.attached.as_ref().expect("attached"), name)
            .expect_err("omitted agent is rejected by SetAgent validation");
    }
}

#[tokio::test]
async fn list_agents_respects_workspace_trust() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".cockpit").join("agents")).unwrap();
    std::fs::write(
        tmp.path().join(".cockpit").join("agents").join("Custom.md"),
        "---\ndescription: custom primary\nmode: primary\n---\nBody\n",
    )
    .unwrap();
    let ctx = test_ctx();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        )
        .unwrap();
    state
        .attached
        .as_mut()
        .expect("attached")
        .handle
        .trust_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
    };

    let response = handle_request(Request::ListAgents, &mut state, &ctx)
        .await
        .expect("list agents succeeds under ignore-config trust");
    let Response::Agents { agents } = response else {
        panic!("expected agents response");
    };

    assert!(
        !agents.iter().any(|agent| agent.name == "Custom"),
        "repo-local custom agents are hidden under ignore-config trust"
    );
}

#[tokio::test]
async fn list_models_returns_resolved_models() {
    use crate::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry};

    let mut providers = std::collections::BTreeMap::new();
    providers.insert(
        "openai".to_string(),
        ProviderEntry {
            url: "https://api.openai.example/v1".to_string(),
            models: vec![
                ModelEntry {
                    id: "gpt-b".to_string(),
                    name: Some("GPT B".to_string()),
                    favorite: false,
                    ..ModelEntry::default()
                },
                ModelEntry {
                    id: "gpt-a".to_string(),
                    name: Some("GPT A".to_string()),
                    favorite: true,
                    ..ModelEntry::default()
                },
            ],
            ..ProviderEntry::default()
        },
    );
    providers.insert(
        "anthropic".to_string(),
        ProviderEntry {
            url: "https://api.anthropic.example/v1".to_string(),
            models: vec![ModelEntry {
                id: "claude".to_string(),
                name: Some("Claude".to_string()),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let providers_cfg = crate::config::providers::ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "openai".to_string(),
            model: "gpt-a".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..crate::config::providers::ProvidersConfig::default()
    };
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        providers_cfg,
        crate::config::extended::ExtendedConfig::default(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let response = handle_request(Request::ListModels { provider: None }, &mut state, &ctx)
        .await
        .expect("list models succeeds");
    let Response::Models { models } = response else {
        panic!("expected models response");
    };

    assert_eq!(
        models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>(),
        vec!["gpt-a", "gpt-b"]
    );
    assert_eq!(models[0].provider, "openai");
    assert_eq!(models[0].display_name.as_deref(), Some("GPT A"));
    assert!(models[0].favorite);
}

#[tokio::test]
async fn list_models_response_contains_no_secrets() {
    use crate::config::providers::{ActiveModelRef, HeaderSpec, ModelEntry, ProviderEntry};

    let mut providers = std::collections::BTreeMap::new();
    providers.insert(
        "secret-provider".to_string(),
        ProviderEntry {
            url: "https://secret-host.example/v1".to_string(),
            headers: vec![HeaderSpec {
                name: "Authorization".to_string(),
                value: "Bearer super-secret-token".to_string(),
            }],
            credential_ref: Some("credential-secret-ref".to_string()),
            models: vec![ModelEntry {
                id: "safe-model".to_string(),
                name: Some("Safe Model".to_string()),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let providers_cfg = crate::config::providers::ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "secret-provider".to_string(),
            model: "safe-model".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..crate::config::providers::ProvidersConfig::default()
    };
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        providers_cfg,
        crate::config::extended::ExtendedConfig::default(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let response = handle_request(Request::ListModels { provider: None }, &mut state, &ctx)
        .await
        .expect("list models succeeds");
    let rendered = serde_json::to_string(&response).unwrap();

    assert!(rendered.contains("safe-model"));
    assert!(!rendered.contains("super-secret-token"), "{rendered}");
    assert!(!rendered.contains("credential-secret-ref"), "{rendered}");
    assert!(!rendered.contains("secret-host"), "{rendered}");
}

#[tokio::test]
async fn list_models_respects_workspace_trust() {
    let mut providers = std::collections::BTreeMap::new();
    providers.insert(
        "repo-provider".to_string(),
        crate::config::providers::ProviderEntry {
            url: "https://repo.example/v1".to_string(),
            models: vec![crate::config::providers::ModelEntry {
                id: "repo-model".to_string(),
                ..crate::config::providers::ModelEntry::default()
            }],
            ..crate::config::providers::ProviderEntry::default()
        },
    );
    let source = crate::daemon::config_source::ConfigSource::new(
        move |_cwd| {
            let policy = crate::config::trust::runtime_policy();
            let cfg = if policy.as_ref().is_some_and(|policy| {
                policy.mode == crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig
            }) {
                crate::config::providers::ProvidersConfig::default()
            } else {
                crate::config::providers::ProvidersConfig {
                    providers: providers.clone(),
                    ..crate::config::providers::ProvidersConfig::default()
                }
            };
            Ok((cfg, crate::config::extended::ExtendedConfig::default()))
        },
        |_cwd, _provider_id| None,
        |_cwd| crate::daemon::config_source::ConfigWatchPaths::default(),
    );
    let ctx = test_ctx_with_config_source(source);
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        )
        .unwrap();
    state
        .attached
        .as_mut()
        .expect("attached")
        .handle
        .trust_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
    };

    let response = handle_request(Request::ListModels { provider: None }, &mut state, &ctx)
        .await
        .expect("list models succeeds");
    let Response::Models { models } = response else {
        panic!("expected models response");
    };

    assert!(models.is_empty());
}

#[tokio::test]
async fn skill_summary_carries_user_invocable() {
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir_all(skills_dir.join("hidden")).unwrap();
    std::fs::write(
        skills_dir.join("hidden").join("SKILL.md"),
        "---\nname: hidden\ndescription: Hidden from slash\nuser-invocable: false\n---\nBody\n",
    )
    .unwrap();
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.skills.scan_dirs = vec![skills_dir.to_string_lossy().into_owned()];
    extended.skills.external_dirs = Vec::new();
    extended.skills.ancestor_walk = false;
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        crate::config::providers::ProvidersConfig::default(),
        extended,
    ));
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let response = handle_request(
        Request::ListSkills {
            project_root: tmp.path().to_string_lossy().into_owned(),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("list skills succeeds");
    let Response::Skills { skills } = response else {
        panic!("expected skills response");
    };

    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "hidden");
    assert!(!skills[0].user_invocable);
    let encoded = serde_json::to_value(&skills[0]).unwrap();
    assert!(
        encoded.get("user_invocable").is_some(),
        "field is required on the serialized wire shape: {encoded}"
    );
}

#[tokio::test]
async fn empty_inventories_return_ok_not_error() {
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let models = handle_request(Request::ListModels { provider: None }, &mut state, &ctx)
        .await
        .expect("empty model inventory is ok");
    assert!(matches!(models, Response::Models { models } if models.is_empty()));

    let agents = handle_request(Request::ListAgents, &mut state, &ctx)
        .await
        .expect("builtin fallback agent inventory is ok");
    assert!(matches!(agents, Response::Agents { agents } if !agents.is_empty()));

    let skills = handle_request(
        Request::ListSkills {
            project_root: tmp.path().to_string_lossy().into_owned(),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("empty skill inventory is ok");
    assert!(matches!(skills, Response::Skills { skills } if skills.is_empty()));
}

#[tokio::test]
async fn inventory_ordering_is_stable() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, _) = attached_state(&ctx, tmp.path());

    let first = handle_request(Request::ListAgents, &mut state, &ctx)
        .await
        .expect("first list agents succeeds");
    let second = handle_request(Request::ListAgents, &mut state, &ctx)
        .await
        .expect("second list agents succeeds");
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );

    let first = handle_request(Request::ListModels { provider: None }, &mut state, &ctx)
        .await
        .expect("first list models succeeds");
    let second = handle_request(Request::ListModels { provider: None }, &mut state, &ctx)
        .await
        .expect("second list models succeeds");
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );
}

#[test]
fn response_send_failure_warns_with_request_id_and_no_payload() {
    let request_id = Uuid::new_v4();
    let log = capture_warn_log(|| {
        let error = anyhow::anyhow!("broken pipe while writing envelope");
        log_response_send_failed(request_id, "error", &error);
    });

    assert!(log.contains(&request_id.to_string()));
    assert!(log.contains("envelope_kind=\"error\"") || log.contains("envelope_kind=error"));
    assert!(log.contains("broken pipe"));
    assert!(!log.contains("secret prompt body"));
    assert!(!log.contains("provider_header"));
}

fn test_event_envelope(event: proto::Event) -> EventEnvelope {
    EventEnvelope {
        event,
        redact: std::sync::Arc::new(RedactionTable::empty()),
    }
}

async fn wait_for_shutdown_phase(ctx: &Arc<DaemonContext>, expected: ShutdownPhase) {
    if ctx.shutdown.phase() == expected {
        return;
    }
    let mut phase_rx = ctx.shutdown.subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            phase_rx.changed().await.expect("shutdown signal open");
            if *phase_rx.borrow() == expected {
                break;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("shutdown phase did not reach {expected:?}"));
}

async fn recv_writer_body(
    writer_rx: &mut mpsc::Receiver<ClientWriterMessage>,
    label: &'static str,
) -> Body {
    match writer_rx.recv().await.expect(label) {
        ClientWriterMessage::Envelope(envelope) => envelope.body,
        ClientWriterMessage::EnvelopeWithAck { envelope, .. } => envelope.body,
    }
}

fn fs_read_request(project_root: &std::path::Path, path: &str) -> Request {
    Request::FsRead {
        project_root: project_root.to_string_lossy().into_owned(),
        path: path.to_string(),
        base64: false,
    }
}

fn fs_read_hook_key(project_root: &std::path::Path, path: &str) -> String {
    format!("fs_read:{}:{path}", project_root.to_string_lossy())
}

#[tokio::test]
async fn serialized_requests_apply_in_receipt_order() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let live_session = Arc::new(
        Session::resume(ctx.db.clone(), session.session_id)
            .unwrap()
            .unwrap(),
    );
    let (handle, mut work_rx) =
        SessionWorkerHandle::test_handle_with_receiver(live_session, ctx.registry.locks());
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);

    let (executor_tx, executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, _event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let executor = tokio::spawn(run_client_executor(
        ctx.clone(),
        ClientPrincipal::owner(),
        executor_rx,
        event_cmd_tx,
        writer_tx,
    ));

    let attach_id = Uuid::new_v4();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(
                attach_id,
                Request::Attach {
                    session_id: Some(session.session_id),
                    since_seq: None,
                    project_root: Some(tmp.path().to_string_lossy().into_owned()),
                    no_sandbox: false,
                    interactive: true,
                    model_override: None,
                    client_protocol_version: proto::PROTOCOL_VERSION,
                    env_snapshot: None,
                    env_policy: EnvDriftPolicy::Daemon,
                },
            ),
        ))))
        .await
        .unwrap();
    match recv_writer_body(&mut writer_rx, "attach response").await {
        Body::Response { id, response } => {
            assert_eq!(id, attach_id);
            assert!(matches!(*response, Response::Attached { .. }));
        }
        other => panic!("expected attach response, got {other:?}"),
    }
    assert!(matches!(
        work_rx.recv().await.expect("attach queue hydration"),
        SessionWork::RepublishQueue
    ));

    let set_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(
                set_id,
                Request::SetActiveModel {
                    provider: "openai".to_string(),
                    model: "gpt-5".to_string(),
                    trigger: proto::ActiveModelSwitchTrigger::Daemon,
                    reasoning_effort: None,
                    thinking_mode: None,
                },
            ),
        ))))
        .await
        .unwrap();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(
                message_id,
                Request::SendUserMessage {
                    text: "after model switch".to_string(),
                    display_text: None,
                    tag_expansions: Vec::new(),
                    image_refs: Vec::new(),
                    forced_skill: None,
                },
            ),
        ))))
        .await
        .unwrap();

    match work_rx.recv().await.expect("set-active-model work") {
        SessionWork::SetActiveModel {
            provider,
            model,
            trigger,
            reasoning_effort,
            thinking_mode,
        } => {
            assert_eq!(provider, "openai");
            assert_eq!(model, "gpt-5");
            assert!(matches!(
                trigger,
                crate::session::ModelSwitchTrigger::Daemon
            ));
            assert_eq!(reasoning_effort, None);
            assert_eq!(thinking_mode, None);
        }
        other => panic!("expected SetActiveModel before message, got {other:?}"),
    }
    match work_rx.recv().await.expect("user-message work") {
        SessionWork::UserMessage {
            submission,
            respond_to,
        } => {
            assert_eq!(submission.text, "after model switch");
            let item = proto::QueueItem {
                id: Uuid::new_v4(),
                status: proto::QueueItemStatus::Queued,
                text: submission.text.clone(),
                display_text: None,
                target: proto::QueueTarget::default(),
            };
            respond_to.send((item.clone(), vec![item])).unwrap();
        }
        other => panic!("expected UserMessage after model switch, got {other:?}"),
    }
    let mut saw_set_ack = false;
    let mut saw_message = false;
    for _ in 0..16 {
        match recv_writer_body(&mut writer_rx, "serialized response").await {
            Body::Response { id, response } if id == set_id => {
                assert!(matches!(*response, Response::Ack));
                saw_set_ack = true;
            }
            Body::Response { id, response } if id == message_id => {
                assert!(matches!(*response, Response::UserMessageQueued { .. }));
                saw_message = true;
            }
            Body::Event { .. } => {}
            other => panic!("unexpected serialized response body: {other:?}"),
        }
        if saw_set_ack && saw_message {
            break;
        }
    }
    assert!(saw_set_ack);
    assert!(saw_message);
    drop(executor_tx);
    executor.await.unwrap();
}

#[tokio::test]
async fn concurrent_requests_may_complete_out_of_order() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("slow.txt"), "slow").unwrap();
    std::fs::write(tmp.path().join("fast.txt"), "fast").unwrap();
    let slow_entered = Arc::new(tokio::sync::Notify::new());
    let slow_release = Arc::new(tokio::sync::Notify::new());
    set_concurrent_request_wait_for_test(
        fs_read_hook_key(tmp.path(), "slow.txt"),
        slow_entered.clone(),
        slow_release.clone(),
    );
    let (executor_tx, executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, _event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let executor = tokio::spawn(run_client_executor(
        ctx,
        ClientPrincipal::owner(),
        executor_rx,
        event_cmd_tx,
        writer_tx,
    ));

    let slow_id = Uuid::new_v4();
    let fast_id = Uuid::new_v4();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(slow_id, fs_read_request(tmp.path(), "slow.txt")),
        ))))
        .await
        .unwrap();
    slow_entered.notified().await;
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(fast_id, fs_read_request(tmp.path(), "fast.txt")),
        ))))
        .await
        .unwrap();

    match recv_writer_body(&mut writer_rx, "fast response").await {
        Body::Response { id, response } => {
            assert_eq!(id, fast_id);
            assert!(matches!(*response, Response::FsRead { .. }));
        }
        other => panic!("expected fast response, got {other:?}"),
    }
    slow_release.notify_waiters();
    match recv_writer_body(&mut writer_rx, "slow response").await {
        Body::Response { id, response } => {
            assert_eq!(id, slow_id);
            assert!(matches!(*response, Response::FsRead { .. }));
        }
        other => panic!("expected slow response, got {other:?}"),
    }
    drop(executor_tx);
    executor.await.unwrap();
}

#[tokio::test]
async fn slow_request_does_not_block_event_forwarding() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("slow.txt"), "slow").unwrap();
    let slow_entered = Arc::new(tokio::sync::Notify::new());
    let slow_release = Arc::new(tokio::sync::Notify::new());
    set_concurrent_request_wait_for_test(
        fs_read_hook_key(tmp.path(), "slow.txt"),
        slow_entered.clone(),
        slow_release.clone(),
    );

    let (global_tx, global_rx) = broadcast::channel(8);
    let (event_cmd_tx, event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (executor_tx, executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let event_task = tokio::spawn(run_client_event_forwarder(
        ctx.clone(),
        ClientPrincipal::owner(),
        global_rx,
        event_cmd_rx,
        executor_tx.clone(),
        writer_tx.clone(),
    ));
    let executor = tokio::spawn(run_client_executor(
        ctx,
        ClientPrincipal::owner(),
        executor_rx,
        event_cmd_tx,
        writer_tx,
    ));

    let slow_id = Uuid::new_v4();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(slow_id, fs_read_request(tmp.path(), "slow.txt")),
        ))))
        .await
        .unwrap();
    slow_entered.notified().await;
    global_tx
        .send(test_event_envelope(proto::Event::LspNotice {
            text: "forwarded before slow read response".to_string(),
        }))
        .unwrap();

    match recv_writer_body(&mut writer_rx, "event before slow response").await {
        Body::Event {
            event: proto::Event::LspNotice { text },
        } => assert_eq!(text, "forwarded before slow read response"),
        other => panic!("expected forwarded event, got {other:?}"),
    }
    slow_release.notify_waiters();
    match recv_writer_body(&mut writer_rx, "slow response").await {
        Body::Response { id, response } => {
            assert_eq!(id, slow_id);
            assert!(matches!(*response, Response::FsRead { .. }));
        }
        other => panic!("expected slow response, got {other:?}"),
    }
    event_task.abort();
    drop(executor_tx);
    executor.await.unwrap();
}

#[tokio::test]
async fn concurrent_request_panic_yields_internal_error_and_keeps_connection() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("panic.txt"), "panic").unwrap();
    set_concurrent_request_panic_for_test(fs_read_hook_key(tmp.path(), "panic.txt"));
    let (executor_tx, executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, _event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let executor = tokio::spawn(run_client_executor(
        ctx,
        ClientPrincipal::owner(),
        executor_rx,
        event_cmd_tx,
        writer_tx,
    ));

    let panic_id = Uuid::new_v4();
    let status_id = Uuid::new_v4();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(panic_id, fs_read_request(tmp.path(), "panic.txt")),
        ))))
        .await
        .unwrap();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(status_id, Request::DaemonStatus),
        ))))
        .await
        .unwrap();

    let mut saw_panic_error = false;
    let mut saw_status = false;
    for _ in 0..2 {
        match recv_writer_body(&mut writer_rx, "panic/status response").await {
            Body::Error { id, error } if id == Some(panic_id) => {
                assert_eq!(error.code, ErrorCode::Internal);
                saw_panic_error = true;
            }
            Body::Response { id, response } if id == status_id => {
                assert!(matches!(*response, Response::DaemonStatus { .. }));
                saw_status = true;
            }
            other => panic!("unexpected response after concurrent panic: {other:?}"),
        }
    }
    assert!(saw_panic_error);
    assert!(saw_status);
    drop(executor_tx);
    executor.await.unwrap();
}

#[tokio::test]
async fn blocking_fs_handler_panic_keeps_client_connection() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("panic.txt"), "panic").unwrap();
    crate::daemon::fs_api::set_fs_read_panic_for_test(
        tmp.path().join("panic.txt").canonicalize().unwrap(),
    );
    let (executor_tx, executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, _event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let executor = tokio::spawn(run_client_executor(
        ctx,
        ClientPrincipal::owner(),
        executor_rx,
        event_cmd_tx,
        writer_tx,
    ));

    let panic_id = Uuid::new_v4();
    let status_id = Uuid::new_v4();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(panic_id, fs_read_request(tmp.path(), "panic.txt")),
        ))))
        .await
        .unwrap();
    executor_tx
        .send(ClientExecutorInput::Frame(RecvFrame::Envelope(Box::new(
            Envelope::request(status_id, Request::DaemonStatus),
        ))))
        .await
        .unwrap();

    let mut saw_fs_error = false;
    let mut saw_status = false;
    for _ in 0..2 {
        match recv_writer_body(&mut writer_rx, "fs panic/status response").await {
            Body::Error { id, error } if id == Some(panic_id) => {
                assert_eq!(error.code, ErrorCode::Internal);
                assert_eq!(error.message, "filesystem handler panicked");
                saw_fs_error = true;
            }
            Body::Response { id, response } if id == status_id => {
                assert!(matches!(*response, Response::DaemonStatus { .. }));
                saw_status = true;
            }
            other => panic!("unexpected response after fs handler panic: {other:?}"),
        }
    }
    assert!(saw_fs_error);
    assert!(saw_status);
    drop(executor_tx);
    executor.await.unwrap();
}

#[tokio::test]
async fn concurrent_request_semaphore_applies_backpressure_not_drops() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("read.txt"), "read").unwrap();
    let mut state = MutableClientState::detached_for_test();
    let mut shared = state.shared_snapshot();
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, _event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let mut concurrent = ConcurrentRequestRuntime::with_permits_for_test(0);
    let permits = concurrent.permits.clone();
    let request_id = Uuid::new_v4();
    let mut blocked = Box::pin(handle_envelope(
        Envelope::request(request_id, fs_read_request(tmp.path(), "read.txt")),
        &mut state,
        &mut shared,
        &ctx,
        &event_cmd_tx,
        &writer_tx,
        &mut concurrent,
    ));

    tokio::select! {
        result = &mut blocked => panic!("saturated semaphore should block, got {result:?}"),
        _ = tokio::task::yield_now() => {}
    }
    assert!(writer_rx.try_recv().is_err());
    permits.add_permits(1);
    blocked.await.unwrap();
    match concurrent.join_next().await.expect("concurrent task joins") {
        Ok(()) => {}
        Err(error) => panic!("concurrent task failed: {error}"),
    }
    match recv_writer_body(&mut writer_rx, "response after permit").await {
        Body::Response { id, response } => {
            assert_eq!(id, request_id);
            assert!(matches!(*response, Response::FsRead { .. }));
        }
        other => panic!("expected response after permit, got {other:?}"),
    }
}

#[tokio::test]
async fn client_io_split_slow_request_does_not_block_event_forwarding() {
    let ctx = test_ctx();
    let (global_tx, global_rx) = broadcast::channel(8);
    let (_event_cmd_tx, event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (executor_tx, _executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let event_task = tokio::spawn(run_client_event_forwarder(
        ctx,
        ClientPrincipal::owner(),
        global_rx,
        event_cmd_rx,
        executor_tx,
        writer_tx,
    ));

    global_tx
        .send(test_event_envelope(proto::Event::LspNotice {
            text: "forwarded while executor is unavailable".to_string(),
        }))
        .unwrap();

    match tokio::time::timeout(
        std::time::Duration::from_secs(1),
        recv_writer_body(&mut writer_rx, "writer envelope"),
    )
    .await
    .expect("event forwarded")
    {
        Body::Event {
            event: proto::Event::LspNotice { text },
        } => assert_eq!(text, "forwarded while executor is unavailable"),
        other => panic!("expected forwarded event, got {other:?}"),
    }
    event_task.abort();
}

#[test]
fn client_io_split_writer_is_sole_socket_writer() {
    let source = include_str!("mod.rs");
    let transport_start = source
        .find("async fn handle_client_transport_as")
        .expect("transport function");
    let transport_end = source
        .find("enum ClientExecutorInput")
        .expect("task helpers");
    let transport = &source[transport_start..transport_end];
    assert!(!transport.contains(".send(&Envelope"));
    assert!(!transport.contains(".send(&envelope"));
    assert!(source.contains("async fn run_client_writer"));
    assert!(source.contains("writer.send(&envelope).await"));
}

#[tokio::test]
async fn client_io_split_reader_eof_tears_down_all_tasks() {
    let ctx = test_ctx();
    let (server, client) = tokio::io::duplex(proto::MAX_FRAME_BYTES);
    let task = tokio::spawn(handle_client_transport_as(
        server,
        ctx,
        ClientPrincipal::owner(),
    ));
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .expect("client task exits on reader eof")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn attach_replay_precedes_live_events_under_task_split() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let live_session = Arc::new(
        Session::resume(ctx.db.clone(), session.session_id)
            .unwrap()
            .unwrap(),
    );
    let (handle, _work_rx) =
        SessionWorkerHandle::test_handle_with_receiver(live_session, ctx.registry.locks());
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);
    assert!(ctx.shutdown.begin_drain());

    let mut state = MutableClientState::detached_for_test();
    let mut shared = state.shared_snapshot();
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, mut event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let mut concurrent = ConcurrentRequestRuntime::new();
    let request_id = Uuid::new_v4();
    handle_envelope(
        Envelope::request(
            request_id,
            Request::Attach {
                session_id: Some(session.session_id),
                since_seq: None,
                project_root: Some(tmp.path().to_string_lossy().into_owned()),
                no_sandbox: false,
                interactive: true,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
        ),
        &mut state,
        &mut shared,
        &ctx,
        &event_cmd_tx,
        &writer_tx,
        &mut concurrent,
    )
    .await
    .unwrap();

    assert!(matches!(
        recv_writer_body(&mut writer_rx, "attach response").await,
        Body::Response { .. }
    ));
    let mut saw_drain = false;
    for _ in 0..8 {
        if let Body::Event { event } = recv_writer_body(&mut writer_rx, "attach replay").await
            && matches!(event, proto::Event::DaemonDraining { .. })
        {
            saw_drain = true;
            break;
        }
    }
    assert!(
        saw_drain,
        "attach should enqueue drain replay before live events"
    );
    assert!(matches!(
        event_cmd_rx
            .recv()
            .await
            .expect("live subscription command"),
        ClientEventCommand::Attach(_)
    ));
}

#[tokio::test]
async fn attach_replay_precedes_live_events_under_concurrency() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("slow.txt"), "slow").unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let live_session = Arc::new(
        Session::resume(ctx.db.clone(), session.session_id)
            .unwrap()
            .unwrap(),
    );
    let (handle, _work_rx) =
        SessionWorkerHandle::test_handle_with_receiver(live_session, ctx.registry.locks());
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);
    assert!(ctx.shutdown.begin_drain());

    let slow_entered = Arc::new(tokio::sync::Notify::new());
    let slow_release = Arc::new(tokio::sync::Notify::new());
    set_concurrent_request_wait_for_test(
        fs_read_hook_key(tmp.path(), "slow.txt"),
        slow_entered.clone(),
        slow_release.clone(),
    );
    let mut state = MutableClientState::detached_for_test();
    let mut shared = state.shared_snapshot();
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, mut event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let mut concurrent = ConcurrentRequestRuntime::new();

    let slow_id = Uuid::new_v4();
    handle_envelope(
        Envelope::request(slow_id, fs_read_request(tmp.path(), "slow.txt")),
        &mut state,
        &mut shared,
        &ctx,
        &event_cmd_tx,
        &writer_tx,
        &mut concurrent,
    )
    .await
    .unwrap();
    slow_entered.notified().await;

    let attach_id = Uuid::new_v4();
    handle_envelope(
        Envelope::request(
            attach_id,
            Request::Attach {
                session_id: Some(session.session_id),
                since_seq: None,
                project_root: Some(tmp.path().to_string_lossy().into_owned()),
                no_sandbox: false,
                interactive: true,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
        ),
        &mut state,
        &mut shared,
        &ctx,
        &event_cmd_tx,
        &writer_tx,
        &mut concurrent,
    )
    .await
    .unwrap();

    match recv_writer_body(&mut writer_rx, "attach response").await {
        Body::Response { id, response } => {
            assert_eq!(id, attach_id);
            assert!(matches!(*response, Response::Attached { .. }));
        }
        other => panic!("expected attach response, got {other:?}"),
    }
    let mut saw_drain = false;
    for _ in 0..8 {
        if let Body::Event { event } = recv_writer_body(&mut writer_rx, "attach replay").await
            && matches!(event, proto::Event::DaemonDraining { .. })
        {
            saw_drain = true;
            break;
        }
    }
    assert!(
        saw_drain,
        "attach should enqueue drain replay before slow read response"
    );
    assert!(matches!(
        event_cmd_rx
            .recv()
            .await
            .expect("live subscription command"),
        ClientEventCommand::Attach(_)
    ));
    slow_release.notify_waiters();
    match concurrent.join_next().await.expect("slow read joins") {
        Ok(()) => {}
        Err(error) => panic!("slow read task failed: {error}"),
    }
    match recv_writer_body(&mut writer_rx, "slow response").await {
        Body::Response { id, response } => {
            assert_eq!(id, slow_id);
            assert!(matches!(*response, Response::FsRead { .. }));
        }
        other => panic!("expected slow read response, got {other:?}"),
    }
}

#[tokio::test]
async fn client_io_split_detach_silences_session_events() {
    let ctx = test_ctx();
    let (session_tx, session_rx) = broadcast::channel(8);
    let (_global_tx, global_rx) = broadcast::channel(8);
    let (event_cmd_tx, event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (executor_tx, _executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let event_task = tokio::spawn(run_client_event_forwarder(
        ctx,
        ClientPrincipal::owner(),
        global_rx,
        event_cmd_rx,
        executor_tx,
        writer_tx,
    ));

    event_cmd_tx
        .send(ClientEventCommand::Attach(session_rx))
        .await
        .unwrap();
    session_tx
        .send(test_event_envelope(proto::Event::Notice {
            session_id: Uuid::new_v4(),
            text: "before detach".to_string(),
        }))
        .unwrap();
    assert!(matches!(
        recv_writer_body(&mut writer_rx, "pre-detach event").await,
        Body::Event {
            event: proto::Event::Notice { .. }
        }
    ));

    event_cmd_tx.send(ClientEventCommand::Detach).await.unwrap();
    session_tx
        .send(test_event_envelope(proto::Event::Notice {
            session_id: Uuid::new_v4(),
            text: "after detach".to_string(),
        }))
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), writer_rx.recv())
            .await
            .is_err()
    );
    event_task.abort();
}

#[tokio::test]
async fn client_io_split_global_lag_still_emits_resync_error() {
    let ctx = test_ctx();
    let (global_tx, global_rx) = broadcast::channel(1);
    global_tx
        .send(test_event_envelope(proto::Event::LspNotice {
            text: "first".to_string(),
        }))
        .unwrap();
    global_tx
        .send(test_event_envelope(proto::Event::LspNotice {
            text: "second".to_string(),
        }))
        .unwrap();
    global_tx
        .send(test_event_envelope(proto::Event::LspNotice {
            text: "third".to_string(),
        }))
        .unwrap();

    let (_event_cmd_tx, event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (executor_tx, _executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let event_task = tokio::spawn(run_client_event_forwarder(
        ctx,
        ClientPrincipal::owner(),
        global_rx,
        event_cmd_rx,
        executor_tx,
        writer_tx,
    ));

    let mut saw_error = false;
    for _ in 0..3 {
        let body = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            recv_writer_body(&mut writer_rx, "writer envelope"),
        )
        .await
        .expect("resync envelope");
        if let Body::Error { error, .. } = body {
            assert!(error.message.contains("global event stream lagged"));
            saw_error = true;
            break;
        }
    }
    assert!(saw_error, "global lag should emit a synthetic error");
    event_task.abort();
}

#[tokio::test]
async fn delete_live_session_timeout_leaves_row_intact() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let session = ctx.db.create_session("p", "/x", "Build").unwrap();
    insert_hung_worker(&ctx, session.session_id);

    let err = handle_request(
        Request::DeleteSession {
            session_id: session.session_id,
            cascade: false,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("hung worker should block delete");

    assert_eq!(err.code, ErrorCode::Internal);
    assert!(
        err.message
            .contains("refusing destructive session mutation")
    );
    assert!(ctx.db.get_session(session.session_id).unwrap().is_some());
    assert!(
        ctx.registry
            .active_session_ids()
            .contains(&session.session_id)
    );
}

#[tokio::test]
async fn archive_live_session_timeout_leaves_row_unarchived() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let session = ctx.db.create_session("p", "/x", "Build").unwrap();
    insert_hung_worker(&ctx, session.session_id);

    let err = handle_request(
        Request::ArchiveSession {
            session_id: session.session_id,
            cascade: false,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("hung worker should block archive");

    assert_eq!(err.code, ErrorCode::Internal);
    assert!(
        err.message
            .contains("refusing destructive session mutation")
    );
    let row = ctx
        .db
        .get_session(session.session_id)
        .unwrap()
        .expect("row remains");
    assert!(row.archived_at.is_none());
}

#[tokio::test]
async fn discard_live_ephemeral_session_timeout_leaves_row_intact() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let parent = ctx.db.create_session("p", "/x", "Build").unwrap();
    let side = ctx
        .db
        .create_ephemeral_fork(parent.session_id, None)
        .unwrap();
    insert_hung_worker(&ctx, side.session_id);

    let err = handle_request(
        Request::DiscardSession {
            session_id: side.session_id,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("hung worker should block discard");

    assert_eq!(err.code, ErrorCode::Internal);
    assert!(
        err.message
            .contains("refusing destructive session mutation")
    );
    assert!(ctx.db.get_session(side.session_id).unwrap().is_some());
}

#[tokio::test]
async fn btw_create_rpc_returns_existing_fork_atomically() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let parent = ctx.db.create_session("p", "/x", "Build").unwrap();

    let first = handle_request(
        Request::CreateBtwFork {
            parent_session_id: parent.session_id,
            tangent: false,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("btw create succeeds");
    let Response::BtwFork {
        info: first_info,
        created: true,
    } = first
    else {
        panic!("expected created BtwFork response");
    };

    let second = handle_request(
        Request::CreateBtwFork {
            parent_session_id: parent.session_id,
            tangent: true,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("second btw create succeeds");
    let Response::BtwFork {
        info: second_info,
        created: false,
    } = second
    else {
        panic!("expected existing BtwFork response");
    };

    assert_eq!(first_info.session_id, second_info.session_id);
    assert_eq!(first_info.parent_session_id, parent.session_id);
    assert!(!second_info.tangent);
}

#[tokio::test]
async fn btw_concurrent_with_parent_turn() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    let parent_row = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let parent_session = Arc::new(
        Session::resume(ctx.db.clone(), parent_row.session_id)
            .unwrap()
            .expect("parent session"),
    );
    let (parent_handle, mut parent_rx) =
        SessionWorkerHandle::test_handle_with_receiver(parent_session, ctx.registry.locks());
    let mut parent_state = MutableClientState {
        principal: ClientPrincipal::owner(),
        attached: Some(AttachedSession {
            handle: parent_handle,
            _interactive_guard: None,
        }),
        pending_replay: Vec::new(),
        pending_uploads: HashMap::new(),
        ready_attachments: HashMap::new(),
        upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
        upload_limits: AttachmentUploadLimits::default(),
        terminal_views: HashSet::new(),
        terminal_host: test_terminal_host(),
    };
    let ctx_for_parent = ctx.clone();
    let parent_request = tokio::spawn(async move {
        handle_request(
            Request::SendUserMessage {
                text: "parent work".to_string(),
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs: Vec::new(),
                forced_skill: None,
            },
            &mut parent_state,
            &ctx_for_parent,
        )
        .await
    });
    let SessionWork::UserMessage {
        submission: parent_submission,
        respond_to: parent_respond,
    } = parent_rx.recv().await.expect("parent work queued")
    else {
        panic!("expected parent user message work");
    };
    assert_eq!(parent_submission.text, "parent work");

    let created = ctx.db.create_btw_fork(parent_row.session_id, true).unwrap();
    let btw_session = Arc::new(
        Session::resume(ctx.db.clone(), created.info.session_id)
            .unwrap()
            .expect("btw session"),
    );
    let (btw_handle, mut btw_rx) =
        SessionWorkerHandle::test_handle_with_receiver(btw_session, ctx.registry.locks());
    let mut btw_state = MutableClientState {
        principal: ClientPrincipal::owner(),
        attached: Some(AttachedSession {
            handle: btw_handle,
            _interactive_guard: None,
        }),
        pending_replay: Vec::new(),
        pending_uploads: HashMap::new(),
        ready_attachments: HashMap::new(),
        upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
        upload_limits: AttachmentUploadLimits::default(),
        terminal_views: HashSet::new(),
        terminal_host: test_terminal_host(),
    };
    let ctx_for_btw = ctx.clone();
    let btw_request = tokio::spawn(async move {
        handle_request(
            Request::SendUserMessage {
                text: "btw work".to_string(),
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs: Vec::new(),
                forced_skill: None,
            },
            &mut btw_state,
            &ctx_for_btw,
        )
        .await
    });
    let SessionWork::UserMessage {
        submission: btw_submission,
        respond_to: btw_respond,
    } = tokio::time::timeout(std::time::Duration::from_millis(250), btw_rx.recv())
        .await
        .expect("btw work was not blocked by parent turn")
        .expect("btw work queued")
    else {
        panic!("expected btw user message work");
    };
    assert_eq!(btw_submission.text, "btw work");
    let btw_item = proto::QueueItem {
        id: Uuid::new_v4(),
        status: proto::QueueItemStatus::Queued,
        text: "btw work".to_string(),
        display_text: None,
        target: proto::QueueTarget::default(),
    };
    btw_respond.send((btw_item, Vec::new())).unwrap();
    assert!(matches!(
        btw_request.await.unwrap().unwrap(),
        Response::UserMessageQueued { .. }
    ));

    let parent_item = proto::QueueItem {
        id: Uuid::new_v4(),
        status: proto::QueueItemStatus::Queued,
        text: "parent work".to_string(),
        display_text: None,
        target: proto::QueueTarget::default(),
    };
    parent_respond.send((parent_item, Vec::new())).unwrap();
    assert!(matches!(
        parent_request.await.unwrap().unwrap(),
        Response::UserMessageQueued { .. }
    ));
}

#[tokio::test]
async fn btw_end_rpc_discards_fork() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let parent = ctx.db.create_session("p", "/x", "Build").unwrap();
    let created = ctx.db.create_btw_fork(parent.session_id, false).unwrap();

    let response = handle_request(
        Request::EndBtwFork {
            parent_session_id: parent.session_id,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("btw end succeeds");

    assert!(matches!(response, Response::Ack));
    assert!(
        ctx.db
            .get_session(created.info.session_id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn btw_rehydrate_reports_live_fork() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let parent = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let created = ctx.db.create_btw_fork(parent.session_id, true).unwrap();
    let live_session = Arc::new(
        Session::resume(ctx.db.clone(), parent.session_id)
            .unwrap()
            .expect("session row"),
    );
    let (handle, _work_rx) =
        SessionWorkerHandle::test_handle_with_receiver(live_session, ctx.registry.locks());
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);

    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(
        Request::Attach {
            session_id: Some(parent.session_id),
            since_seq: None,
            project_root: Some(tmp.path().to_string_lossy().into_owned()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: EnvDriftPolicy::Daemon,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("attach succeeds");

    let Response::Attached { btw_fork, .. } = response else {
        panic!("expected Attached response");
    };
    let info = btw_fork.expect("live btw fork reported");
    assert_eq!(info.session_id, created.info.session_id);
    assert_eq!(info.parent_session_id, parent.session_id);
    assert!(info.tangent);
    assert_eq!(info.message_count, 0);
}

#[tokio::test]
async fn cascaded_delete_timeout_stops_before_any_db_mutation() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let root = ctx.db.create_session("p", "/x", "Build").unwrap();
    let child = ctx.db.create_fork(root.session_id, None).unwrap();
    insert_hung_worker(&ctx, child.session_id);

    let err = handle_request(
        Request::DeleteSession {
            session_id: root.session_id,
            cascade: true,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("hung child should block cascaded delete");

    assert_eq!(err.code, ErrorCode::Internal);
    assert!(
        err.message
            .contains("refusing destructive session mutation")
    );
    assert!(ctx.db.get_session(root.session_id).unwrap().is_some());
    assert!(ctx.db.get_session(child.session_id).unwrap().is_some());
}

/// The single graceful-shutdown path
/// (`daemon-graceful-drain-shutdown.md`): the first `request_shutdown`
/// begins the drain and broadcasts the (non-forced) notice; a **second**
/// one while still draining **shortens** to force and broadcasts the
/// forced notice — never a second drain or a reset deadline.
#[tokio::test]
async fn second_stop_request_shortens_to_force() {
    let ctx = test_ctx();
    let mut events = ctx.subscribe_global();
    assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Running);

    // First request: begin drain + non-forced notice.
    request_shutdown(&ctx);
    assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Draining);
    match events.recv().await.expect("drain notice").event {
        proto::Event::DaemonDraining { forced } => assert!(!forced),
        other => panic!("expected DaemonDraining, got {other:?}"),
    }

    // Second request mid-drain: shorten to force + forced notice.
    request_shutdown(&ctx);
    assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Forced);
    match events.recv().await.expect("forced notice").event {
        proto::Event::DaemonDraining { forced } => assert!(forced),
        other => panic!("expected forced DaemonDraining, got {other:?}"),
    }

    // A third request is a no-op — already forced, no further events.
    request_shutdown(&ctx);
    assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Forced);
}

#[tokio::test]
async fn stop_daemon_grace_override_reaches_shutdown_context() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();

    let response = handle_request(
        Request::StopDaemon {
            grace_secs: Some(7),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("stop daemon ack");

    assert!(matches!(response, Response::Ack));
    assert_eq!(
        ctx.take_shutdown_grace_override(),
        Some(std::time::Duration::from_secs(7))
    );
    assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Draining);
}

/// `/note` (`RecordSessionNote`) records a durable `user_note` session
/// event and returns its `seq` — without enqueueing any work on a worker
/// (no inference). The event is queryable for export immediately.
#[tokio::test]
async fn record_session_note_persists_event_without_inference() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let s = ctx.db.create_session("p", "/x", "Build").unwrap();

    let resp = handle_request(
        Request::RecordSessionNote {
            session_id: s.session_id,
            text: "remember the retry change broke it".into(),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("note recorded");
    let seq = match resp {
        Response::NoteRecorded { seq } => seq,
        other => panic!("expected NoteRecorded, got {other:?}"),
    };
    assert!(seq > 0);

    // The event landed durably with its discriminant + verbatim text, and
    // no worker/turn was started (no AttachedSession was ever created).
    let events = ctx.db.list_session_events(s.session_id).unwrap();
    assert_eq!(
        events.len(),
        1,
        "exactly the note event — no inference turn"
    );
    assert_eq!(events[0].kind, "user_note");
    assert_eq!(
        events[0].data.get("text").and_then(|v| v.as_str()),
        Some("remember the retry change broke it")
    );
    assert!(state.attached.is_none(), "no worker attached / spawned");
}

/// `RecordSessionNote` for an unknown session is an `UnknownSession` error
/// — never a phantom session created just to hold the note.
#[tokio::test]
async fn record_session_note_unknown_session_errors() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let err = handle_request(
        Request::RecordSessionNote {
            session_id: Uuid::new_v4(),
            text: "x".into(),
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("unknown session must error");
    assert_eq!(err.code, ErrorCode::UnknownSession);
}

/// New-user-work gate: once draining, `SendUserMessage` is refused with
/// the `Shutdown` error code rather than dropped or queued.
#[tokio::test]
async fn send_user_message_refused_while_draining() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();

    ctx.shutdown.begin_drain();

    let err = handle_request(
        Request::SendUserMessage {
            text: "hi".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: vec![],
            forced_skill: None,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("draining daemon must refuse new user messages");
    assert_eq!(err.code, ErrorCode::Shutdown);
}

#[tokio::test]
async fn resync_drain_state_sends_nothing_while_running() {
    let ctx = test_ctx();
    let (left, right) = tokio::io::duplex(proto::MAX_FRAME_BYTES);
    let mut server = ProtoStream::new(left);
    let mut client = ProtoStream::new(right);

    ctx.resync_drain_state(&mut server)
        .await
        .expect("running resync should not fail");

    let recv = tokio::time::timeout(std::time::Duration::from_millis(20), client.recv()).await;
    assert!(recv.is_err(), "running phase should not emit an envelope");
}

#[tokio::test]
async fn resync_drain_state_replays_draining_and_forced() {
    let ctx = test_ctx();
    let (left, right) = tokio::io::duplex(proto::MAX_FRAME_BYTES);
    let mut server = ProtoStream::new(left);
    let mut client = ProtoStream::new(right);

    assert!(ctx.shutdown.begin_drain());
    ctx.resync_drain_state(&mut server)
        .await
        .expect("draining resync");
    match recv_body(&mut client).await {
        Body::Event {
            event: proto::Event::DaemonDraining { forced },
        } => assert!(!forced),
        other => panic!("expected non-forced DaemonDraining, got {other:?}"),
    }

    ctx.shutdown.force();
    ctx.resync_drain_state(&mut server)
        .await
        .expect("forced resync");
    match recv_body(&mut client).await {
        Body::Event {
            event: proto::Event::DaemonDraining { forced },
        } => assert!(forced),
        other => panic!("expected forced DaemonDraining, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_replays_drain_state_after_attached_response() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let live_session = Arc::new(
        Session::resume(ctx.db.clone(), session.session_id)
            .unwrap()
            .expect("session row"),
    );
    let (handle, _work_rx) =
        SessionWorkerHandle::test_handle_with_receiver(live_session, ctx.registry.locks());
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);
    assert!(ctx.shutdown.begin_drain());

    let mut state = MutableClientState::detached_for_test();
    let mut shared = state.shared_snapshot();
    let (writer_tx, mut writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, _event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let mut concurrent = ConcurrentRequestRuntime::new();
    let request_id = Uuid::new_v4();
    handle_envelope(
        Envelope::request(
            request_id,
            Request::Attach {
                session_id: Some(session.session_id),
                since_seq: None,
                project_root: Some(tmp.path().to_string_lossy().into_owned()),
                no_sandbox: false,
                interactive: true,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
        ),
        &mut state,
        &mut shared,
        &ctx,
        &event_cmd_tx,
        &writer_tx,
        &mut concurrent,
    )
    .await
    .expect("attach envelope handled");

    match recv_writer_body(&mut writer_rx, "response").await {
        Body::Response { id, response } => {
            let Response::Attached { session_id, .. } = *response else {
                panic!("expected Attached response, got {response:?}");
            };
            assert_eq!(id, request_id);
            assert_eq!(session_id, session.session_id);
        }
        other => panic!("expected Attached response, got {other:?}"),
    }
    let mut saw_drain = false;
    for _ in 0..8 {
        match recv_writer_body(&mut writer_rx, "drain state replay").await {
            Body::Event {
                event: proto::Event::DaemonDraining { forced },
            } => {
                assert!(!forced);
                saw_drain = true;
                break;
            }
            Body::Event { .. } => {}
            other => panic!("expected replay event, got {other:?}"),
        }
    }
    assert!(saw_drain, "expected DaemonDraining replay");
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_since_seq_queues_history_replay_and_leaves_attached_history_empty() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
    let session = ctx
        .db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let seq1 = ctx
        .db
        .insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "already applied"}),
        )
        .unwrap();
    let seq2 = ctx
        .db
        .insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "missed while disconnected"}),
        )
        .unwrap();
    let live_session = Arc::new(
        Session::resume(ctx.db.clone(), session.session_id)
            .unwrap()
            .expect("session row"),
    );
    let (handle, _work_rx) =
        SessionWorkerHandle::test_handle_with_receiver(live_session, ctx.registry.locks());
    let join = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    ctx.registry.insert_test_worker(handle, join);

    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(
        Request::Attach {
            session_id: Some(session.session_id),
            since_seq: Some(seq1),
            project_root: Some(tmp.path().to_string_lossy().into_owned()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: EnvDriftPolicy::Daemon,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("since_seq attach succeeds");

    let Response::Attached { history, .. } = response else {
        panic!("expected Attached response");
    };
    assert!(
        history.is_empty(),
        "since_seq attach flushes replay after Attached, not inside response history"
    );
    let replay = state
        .pending_replay
        .iter()
        .find_map(|event| match event {
            proto::Event::HistoryReplay {
                session_id,
                entries,
                max_seq,
            } => Some((*session_id, entries, *max_seq)),
            _ => None,
        })
        .expect("pending history replay");
    let (session_id, entries, max_seq) = replay;
    assert_eq!(session_id, session.session_id);
    assert_eq!(max_seq, seq2);
    assert_eq!(entries.len(), 1);
    match &entries[0] {
        proto::HistoryEntry::User { text, seq, .. } => {
            assert_eq!(text, "missed while disconnected");
            assert_eq!(*seq, seq2);
        }
        other => panic!("expected replayed user message, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_compatible_reflects_client_protocol_version() {
    let ctx = test_ctx();
    let tmp = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();

    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(
        Request::Attach {
            session_id: None,
            since_seq: None,
            project_root: Some(tmp.path().to_string_lossy().into_owned()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: 0,
            env_snapshot: None,
            env_policy: EnvDriftPolicy::Daemon,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("old client attaches");
    match response {
        Response::Attached { compatible, .. } => assert!(!compatible),
        other => panic!("expected Attached, got {other:?}"),
    }

    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(
        Request::Attach {
            session_id: None,
            since_seq: None,
            project_root: Some(tmp.path().to_string_lossy().into_owned()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: EnvDriftPolicy::Daemon,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("current client attaches");
    match response {
        Response::Attached { compatible, .. } => assert!(compatible),
        other => panic!("expected Attached, got {other:?}"),
    }
}

/// Regression (`daemon-trust-test-isolation.md`): daemon attach resolves
/// the session's model from the [`ConfigSource`] injected through the
/// `DaemonContext` constructor — never from the machine's live layered
/// config. On a machine whose `~/.config/cockpit` enables trusted-only
/// with an untrusted active model (the exact condition that redded the
/// dispatch-matrix tests), this passes only if the attach path consults
/// the seam.
#[tokio::test]
async fn attach_resolves_model_from_injected_config_source() {
    use crate::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry};

    let mut providers = std::collections::BTreeMap::new();
    providers.insert(
        "lmstudio".to_string(),
        ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            models: vec![ModelEntry {
                id: "injected-model".to_string(),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let providers_cfg = crate::config::providers::ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "lmstudio".to_string(),
            model: "injected-model".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..crate::config::providers::ProvidersConfig::default()
    };
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        providers_cfg,
        crate::config::extended::ExtendedConfig::default(),
    ));
    let tmp = tempfile::tempdir().unwrap();
    ctx.db
        .set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();

    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(
        Request::Attach {
            session_id: None,
            since_seq: None,
            project_root: Some(tmp.path().to_string_lossy().into_owned()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: EnvDriftPolicy::Daemon,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect("attach resolves the injected model without reading live config");
    match response {
        Response::Attached {
            active_model_state: Some(active),
            ..
        } => {
            assert_eq!(active.provider, "lmstudio");
            assert_eq!(active.model, "injected-model");
            assert_eq!(active.config_provider.as_deref(), Some("lmstudio"));
            assert_eq!(active.config_model.as_deref(), Some("injected-model"));
            assert!(!active.diverged);
        }
        other => panic!("expected Attached, got {other:?}"),
    }

    let att = state.attached.as_ref().expect("client is attached");
    assert_eq!(
        att.handle.active_model_selection(),
        (
            Some("lmstudio".to_string()),
            Some("injected-model".to_string())
        ),
        "session active model must match the injected config source"
    );
}

#[tokio::test]
async fn server_answers_too_new_request_with_protocol_version_error() {
    let ctx = test_ctx();
    let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
    let server = tokio::spawn(handle_client(server_stream, ctx));
    let mut client = ProtoStream::new(client_stream);

    // Initial hello + caffeinate snapshot.
    let _ = recv_body(&mut client).await;
    let _ = recv_body(&mut client).await;

    let id = Uuid::new_v4();
    client
        .send_raw_line(
            serde_json::json!({
                "v": 999,
                "kind": "req",
                "id": id,
                "request": "daemon_status"
            })
            .to_string(),
        )
        .await
        .unwrap();

    match recv_body(&mut client).await {
        Body::Error {
            id: Some(got_id),
            error,
        } => {
            assert_eq!(got_id, id);
            assert_eq!(error.code, ErrorCode::ProtocolVersion);
            assert!(error.message.contains("wire protocol version mismatch"));
        }
        other => panic!("expected protocol version error, got {other:?}"),
    }
    assert!(client.recv().await.unwrap().is_none());
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn attach_requires_db_workspace_trust_row() {
    let ctx = test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let tmp = tempfile::tempdir().unwrap();

    let err = handle_request(
        Request::Attach {
            session_id: None,
            since_seq: None,
            project_root: Some(tmp.path().to_string_lossy().into_owned()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: EnvDriftPolicy::Daemon,
        },
        &mut state,
        &ctx,
    )
    .await
    .expect_err("daemon attach must fail closed without a trust row");

    assert_eq!(err.code, ErrorCode::WorkspaceTrust);
    assert_eq!(
        err.message,
        crate::config::trust::WorkspaceTrustError::Unset {
            root: tmp.path().canonicalize().unwrap(),
        }
        .to_string()
    );
    assert!(!err.to_string().contains("internal:"));
    assert!(state.attached.is_none());
}

#[test]
fn daemon_load_configs_uses_session_policy_over_global_policy() {
    let _env = crate::test_env::lock();
    let trusted = tempfile::tempdir().unwrap();
    let ignored = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(trusted.path().join(".cockpit")).unwrap();
    std::fs::create_dir_all(ignored.path().join(".cockpit")).unwrap();
    std::fs::write(
        ignored.path().join(".cockpit").join("config.json"),
        r#"{"max_primary_rounds": 77}"#,
    )
    .unwrap();

    crate::config::trust::clear_runtime_policy_for_tests();
    let global_root = crate::config::trust::resolve_trust_root(trusted.path()).unwrap();
    crate::config::trust::set_runtime_policy(
        global_root,
        crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    );
    let session_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(ignored.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
    };

    let (_, extended) = crate::daemon::config_source::ConfigSource::production()
        .load_with_trust(ignored.path(), &session_policy)
        .unwrap();

    assert_ne!(extended.max_primary_rounds, 77);
    crate::config::trust::clear_runtime_policy_for_tests();
}

#[test]
fn response_redaction_scrubs_queue_display_metadata() {
    crate::auth::flycockpit::with_redaction_token_override("fci_response_secret_12345", || {
        let tmp = tempfile::tempdir().unwrap();
        let table = crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            tmp.path(),
        )
        .unwrap();
        let item = proto::QueueItem {
            id: Uuid::new_v4(),
            status: proto::QueueItemStatus::Queued,
            text: "wire fci_response_secret_12345".to_string(),
            display_text: Some("review @fci_response_secret_12345".to_string()),
            target: proto::QueueTarget::default(),
        };
        let response = scrub_proto_response(
            Response::UserMessageQueued {
                item: item.clone(),
                queue: vec![item],
            },
            &table,
        )
        .expect("redacted response");
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains("fci_response_secret_12345"), "{encoded}");
        assert!(encoded.contains("REDACT"), "{encoded}");
    });
}

#[test]
fn redaction_preserves_uuid_when_secret_overlaps() {
    crate::auth::flycockpit::with_redaction_token_override("88c0e13f", || {
        let tmp = tempfile::tempdir().unwrap();
        let table = crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            tmp.path(),
        )
        .unwrap();
        let id = Uuid::parse_str("88c0e13f-486b-4cfc-8c8f-31dd49b4d39f").unwrap();
        let item = proto::QueueItem {
            id,
            status: proto::QueueItemStatus::Queued,
            text: "wire 88c0e13f".to_string(),
            display_text: Some("review @88c0e13f".to_string()),
            target: proto::QueueTarget::default(),
        };

        let scrubbed = scrub_proto_response(
            Response::UserMessageQueued {
                item: item.clone(),
                queue: vec![item],
            },
            &table,
        )
        .expect("overlap redaction must not drop response");

        let Response::UserMessageQueued { item, queue } = scrubbed else {
            panic!("expected queued response");
        };
        assert_eq!(item.id, id);
        assert_eq!(queue[0].id, id);
        assert!(!item.text.contains("88c0e13f"), "{item:?}");
        assert!(
            !item
                .display_text
                .as_deref()
                .unwrap_or_default()
                .contains("88c0e13f"),
            "{item:?}"
        );
        let encoded = serde_json::to_string(&Response::UserMessageQueued { item, queue }).unwrap();
        assert!(!encoded.contains("88c0e13f\""), "{encoded}");
        assert!(encoded.contains("REDACT"), "{encoded}");
    });
}

#[test]
fn event_redaction_preserves_typed_fields() {
    crate::auth::flycockpit::with_redaction_token_override("88c0e13f", || {
        let tmp = tempfile::tempdir().unwrap();
        let table = crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            tmp.path(),
        )
        .unwrap();
        let session_id = Uuid::parse_str("88c0e13f-486b-4cfc-8c8f-31dd49b4d39f").unwrap();
        let item_id = Uuid::parse_str("99c0e13f-486b-4cfc-8c8f-31dd49b4d399").unwrap();
        let event = proto::Event::QueueUpdated {
            session_id,
            queue: vec![proto::QueueItem {
                id: item_id,
                status: proto::QueueItemStatus::Queued,
                text: "wire 88c0e13f".to_string(),
                display_text: Some("review @88c0e13f".to_string()),
                target: proto::QueueTarget::default(),
            }],
        };

        let scrubbed =
            scrub_proto_event(event, &table).expect("overlap redaction must not drop event");
        let proto::Event::QueueUpdated {
            session_id: got,
            queue,
        } = scrubbed
        else {
            panic!("expected queue event");
        };
        assert_eq!(got, session_id);
        assert_eq!(queue[0].id, item_id);
        let encoded = serde_json::to_string(&proto::Event::QueueUpdated {
            session_id: got,
            queue,
        })
        .unwrap();
        assert!(!encoded.contains("wire 88c0e13f"), "{encoded}");
        assert!(!encoded.contains("review @88c0e13f"), "{encoded}");
        assert!(encoded.contains("REDACT"), "{encoded}");
    });
}

#[test]
fn redaction_preserves_structural_string_fields() {
    crate::auth::flycockpit::with_redaction_token_override("secret-struct", || {
        let tmp = tempfile::tempdir().unwrap();
        let table = crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            tmp.path(),
        )
        .unwrap();

        let turn_id = "turn-secret-struct-123".to_string();
        let event = scrub_proto_event(
            proto::Event::ThinkingStarted {
                session_id: Uuid::new_v4(),
                agent: "Build-secret-struct".to_string(),
                turn_id: Some(turn_id.clone()),
            },
            &table,
        )
        .expect("structural event strings must not drop event");
        let proto::Event::ThinkingStarted {
            agent,
            turn_id: got_turn_id,
            ..
        } = event
        else {
            panic!("expected thinking event");
        };
        assert_eq!(agent, "Build-secret-struct");
        assert_eq!(got_turn_id.as_deref(), Some(turn_id.as_str()));

        let fork_point_turn_id = "fork-secret-struct-456".to_string();
        let forked = scrub_proto_response(
            Response::Forked {
                session_id: Uuid::new_v4(),
                short_id: "abc123".to_string(),
                parent_session_id: Uuid::new_v4(),
                fork_point_turn_id: Some(fork_point_turn_id.clone()),
            },
            &table,
        )
        .expect("structural response strings must not drop response");
        let Response::Forked {
            fork_point_turn_id: got_fork_point_turn_id,
            ..
        } = forked
        else {
            panic!("expected forked response");
        };
        assert_eq!(
            got_fork_point_turn_id.as_deref(),
            Some(fork_point_turn_id.as_str())
        );

        let models = scrub_proto_response(
            Response::Models {
                models: vec![proto::ModelSummary {
                    provider: "provider-secret-struct".to_string(),
                    id: "model-secret-struct".to_string(),
                    display_name: Some("Secret model secret-struct".to_string()),
                    favorite: false,
                }],
            },
            &table,
        )
        .expect("catalog model response must not drop response");
        let Response::Models { models } = models else {
            panic!("expected models response");
        };
        assert_eq!(models[0].provider, "provider-secret-struct");
        assert_eq!(models[0].id, "model-secret-struct");
        assert!(
            !models[0]
                .display_name
                .as_deref()
                .unwrap_or_default()
                .contains("secret-struct"),
            "{models:?}"
        );
    });
}

#[test]
fn history_redaction_preserves_typed_fields() {
    crate::auth::flycockpit::with_redaction_token_override("call-secret-123", || {
        let tmp = tempfile::tempdir().unwrap();
        let table = crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            tmp.path(),
        )
        .unwrap();
        let call_id = "call-secret-123-structural-id".to_string();
        let entry = proto::HistoryEntry::ToolCall {
            seq: 9,
            agent: "Build".to_string(),
            call_id: call_id.clone(),
            parent_call_id: None,
            parent_child_index: None,
            tool: "bash".to_string(),
            mcp_server: None,
            mcp_builtin: None,
            mcp_kind: None,
            original_input: serde_json::json!({"cmd": "echo call-secret-123"}),
            wire_input: serde_json::json!({"cmd": "echo call-secret-123"}),
            recovery_kind: None,
            recovery_stage: None,
            output: "result call-secret-123".to_string(),
            hard_fail: false,
            truncated: false,
            hint: Some("hint call-secret-123".to_string()),
        };

        let scrubbed =
            scrub_history_entry(entry, &table).expect("overlap redaction must not drop history");
        let proto::HistoryEntry::ToolCall {
            call_id: got,
            output,
            hint,
            original_input,
            wire_input,
            ..
        } = scrubbed
        else {
            panic!("expected tool-call history");
        };
        assert_eq!(got, call_id);
        let encoded = serde_json::to_string(&(output, hint, original_input, wire_input)).unwrap();
        assert!(!encoded.contains("call-secret-123"), "{encoded}");
        assert!(encoded.contains("REDACT"), "{encoded}");
    });
}

#[test]
fn history_redaction_scrubs_display_text_and_tag_expansions() {
    crate::auth::flycockpit::with_redaction_token_override("fci_history_secret_12345", || {
        let tmp = tempfile::tempdir().unwrap();
        let table = crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            tmp.path(),
        )
        .unwrap();
        let entry = proto::HistoryEntry::User {
            text: "wire fci_history_secret_12345".to_string(),
            display_text: Some("review @fci_history_secret_12345".to_string()),
            tag_expansions: vec![proto::TagExpansionMeta {
                tool: "read".to_string(),
                path: "fci_history_secret_12345.rs".to_string(),
                detail: "fci_history_secret_12345 lines".to_string(),
                ok: true,
            }],
            ts_ms: 0,
            seq: 1,
            origin_principal: Some("flycockpit:remote".to_string()),
        };
        let scrubbed = scrub_history_entry(entry, &table).expect("redacted history");
        let encoded = serde_json::to_string(&scrubbed).unwrap();
        assert!(!encoded.contains("fci_history_secret_12345"), "{encoded}");
        assert!(encoded.contains("REDACT"), "{encoded}");
    });
}
