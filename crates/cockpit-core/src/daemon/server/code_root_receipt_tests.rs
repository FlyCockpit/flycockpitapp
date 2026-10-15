//! Receipt retries cross the real connection dispatcher and session worker.
//! The global source stays healthy while only workspace capture is refused.

use super::*;

const OLD_SECRET: &str = "receipt-old-token-547-keep-protected";
const NEW_SECRET: &str = "receipt-new-token-547-keep-protected";
const PUBLIC_HISTORY: &str = "Public frozen history";
const PUBLIC_TITLE: &str = "Public frozen title";
const LATER_HISTORY: &str = "Later row must not enter the frozen receipt";

struct ReceiptConnection {
    client: ProtoStream<tokio::io::DuplexStream>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl ReceiptConnection {
    async fn open(ctx: &Arc<DaemonContext>) -> Self {
        let (server, client) = tokio::io::duplex(proto::MAX_NDJSON_FRAME_BYTES);
        let server = tokio::spawn(handle_client_transport_as(
            server,
            ctx.clone(),
            ClientPrincipal::owner(),
            Uuid::new_v4(),
            true,
            None,
        ));
        let mut client = ProtoStream::new(client);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(10), recv_body(&mut client))
                .await
                .expect("connection hello"),
            Body::Response { id, response }
                if id == Uuid::nil() && matches!(*response, Response::DaemonStatus { .. })
        ));
        Self { client, server }
    }

    /// The dispatcher barrier in `project` does not fence the independent
    /// worker/driver tasks. Observe real startup publication before measuring
    /// replay side effects; never mistake late committed startup transitions
    /// for duplicate receipt deliveries.
    async fn settle_worker_startup(
        &mut self,
        ctx: &DaemonContext,
        session_id: Uuid,
        mut events: Vec<proto::Event>,
    ) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while !events.iter().any(|event| {
                matches!(event, proto::Event::ContextProjection { session_id: id, .. }
                    if *id == session_id)
            }) {
                match recv_body(&mut self.client).await {
                    Body::Event { event } => events.push(event),
                    other => panic!("worker startup event: {other:?}"),
                }
            }
            let committed = ctx
                .db
                .latest_agent_tree_event_seq(session_id)
                .await
                .unwrap()
                .expect("startup committed the root agent-tree transitions");
            while !events.iter().any(|event| {
                matches!(event, proto::Event::AgentTreeChanged {
                    session_id: id, session_event_seq, ..
                } if *id == session_id && *session_event_seq >= committed)
            }) {
                match recv_body(&mut self.client).await {
                    Body::Event { event } => events.push(event),
                    other => panic!("committed startup relay: {other:?}"),
                }
            }
        })
        .await
        .expect("worker startup publications arrive before receipt replay");
    }

    /// A serialized status request is a barrier after all attach replay events.
    /// This proves a notice was delivered for this attempt, without sleeps or
    /// accepting a previous connection's coverage state.
    async fn project(
        &mut self,
        request: &Request,
    ) -> (
        proto::CodeRootAttachmentV1,
        proto::CodeRootReadV1,
        Vec<proto::Event>,
    ) {
        tokio::time::timeout(Duration::from_secs(20), async {
            let id = Uuid::now_v7();
            self.client
                .send(&Envelope::request(id, request.clone()))
                .await
                .expect("send exact logical request");
            let mut events = Vec::new();
            let response = loop {
                match recv_body(&mut self.client).await {
                    Body::Event { event } => events.push(event),
                    Body::Response { id: got, response } => {
                        assert_eq!(got, id);
                        break *response;
                    }
                    other => panic!("Code-root response: {other:?}"),
                }
            };
            let (attachment, root) = match (request, response) {
                (Request::CreateCodeRootV1(_), Response::CodeRootCreated(result)) => {
                    (result.attachment, result.root)
                }
                (Request::AttachExistingCodeRootV1(_), Response::CodeRootAttached(result)) => {
                    (result.attachment, result.root)
                }
                (
                    Request::CreateCodeRootWithAcpIngressV1(_),
                    Response::CodeRootWithAcpIngressCreated(result),
                ) => (result.base.attachment, result.base.root),
                (
                    Request::AttachExistingCodeRootWithAcpIngressV1(_),
                    Response::CodeRootWithAcpIngressAttached(result),
                ) => (result.base.attachment, result.base.root),
                (_, other) => panic!("matching Code-root route result: {other:?}"),
            };
            let barrier = Uuid::now_v7();
            self.client
                .send(&Envelope::request(barrier, Request::DaemonStatus))
                .await
                .expect("send replay barrier");
            loop {
                match recv_body(&mut self.client).await {
                    Body::Event { event } => events.push(event),
                    Body::Response { id: got, response } => {
                        assert_eq!(got, barrier);
                        assert!(matches!(*response, Response::DaemonStatus { .. }));
                        break;
                    }
                    other => panic!("replay barrier response: {other:?}"),
                }
            }
            (attachment, root, events)
        })
        .await
        .expect("bounded live dispatcher projection")
    }

    async fn ack(&mut self, request: Request) {
        let id = Uuid::now_v7();
        self.client
            .send(&Envelope::request(id, request))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match recv_body(&mut self.client).await {
                    Body::Event { .. } => {}
                    Body::Response { id: got, response } => {
                        assert_eq!(got, id);
                        assert!(matches!(*response, Response::Ack));
                        break;
                    }
                    other => panic!("paused-work transition response: {other:?}"),
                }
            }
        })
        .await
        .expect("paused-work transition completes");
    }

    async fn close(self) {
        drop(self.client);
        match tokio::time::timeout(Duration::from_secs(10), self.server)
            .await
            .expect("connection teardown")
            .expect("connection task joins")
        {
            Ok(()) => {}
            Err(error) => {
                let text = format!("{error:#}");
                assert!(
                    text.contains("Connection reset")
                        || text.contains("ended unexpectedly")
                        || text.contains("broken pipe")
                        || text.contains("Broken pipe")
                        || text.contains("early eof"),
                    "connection teardown: {text}"
                );
            }
        }
    }
}

fn composed_create(base: proto::CreateCodeRootV1Request, acp: bool) -> Request {
    if acp {
        Request::CreateCodeRootWithAcpIngressV1(proto::CreateCodeRootWithAcpIngressV1Request {
            base,
            ingress: receipt_ingress(),
        })
    } else {
        Request::CreateCodeRootV1(base)
    }
}

fn composed_attach(base: proto::AttachExistingCodeRootV1Request, acp: bool) -> Request {
    if acp {
        Request::AttachExistingCodeRootWithAcpIngressV1(
            proto::AttachExistingCodeRootWithAcpIngressV1Request {
                base,
                ingress: receipt_ingress(),
            },
        )
    } else {
        Request::AttachExistingCodeRootV1(base)
    }
}

fn receipt_ingress() -> proto::AcpForwardedMcpIngressV1 {
    proto::AcpForwardedMcpIngressV1 {
        version: 1,
        declarations: Vec::new(),
        client_provenance_id: proto::OpaqueAsciiId128V1::new("receipt-client").unwrap(),
        ingress_request_id: proto::OpaqueAsciiId128V1::new("receipt-ingress").unwrap(),
    }
}

fn assert_coverage(
    events: &[proto::Event],
    session_id: Uuid,
    expected: Option<proto::RedactionCoverageFailure>,
) {
    let scoped: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            proto::Event::RedactionCoverageStatus {
                session_id: Some(id),
                unavailable,
            } if *id == session_id => Some(*unavailable),
            _ => None,
        })
        .collect();
    assert_eq!(
        scoped,
        vec![expected],
        "each return projects exactly once and delivers its current session-scoped status"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            proto::Event::RedactionCoverageStatus {
                session_id: None,
                unavailable: None,
            }
        )),
        "workspace capture refusal must coexist with healthy global coverage"
    );
}

fn assert_same_receipt(
    original: &proto::CodeRootAttachmentV1,
    retry: &proto::CodeRootAttachmentV1,
    root: &proto::CodeRootReadV1,
) {
    assert_eq!(retry.root_id, original.root_id);
    assert_eq!(root.root_id, original.root_id);
    assert_eq!(retry.capture_generation, original.capture_generation);
    assert_eq!(retry.replay_cursor, original.replay_cursor);
    assert_ne!(retry.attachment_capability, original.attachment_capability);
}

#[derive(Clone, Copy)]
enum ReceiptRoute {
    Create,
    RecoveredCreate,
    Attach,
}

async fn exercise_receipt_projection(route: ReceiptRoute, acp: bool) {
    let project = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(project.path()).unwrap();
    let dotenv = workspace.join(".env");
    std::fs::write(&dotenv, format!("TOKEN={OLD_SECRET}\n")).unwrap();
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.redact.scan_ssh_keys = false;
    extended.redact.scan_dotenv = true;
    let ctx = test_ctx_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
        stub_providers_config(),
        extended,
    ));
    ctx.db
        .set_workspace_trust(
            &workspace,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .await
        .unwrap();
    let mut connection = ReceiptConnection::open(&ctx).await;
    let Request::CreateCodeRootV1(base_create) = proto::create_code_root_v1_request(
        workspace.to_string_lossy().into_owned(),
        None,
        false,
        true,
        None,
        None,
        proto::EnvDriftPolicy::Daemon,
    ) else {
        panic!("create request constructor");
    };
    let create = composed_create(base_create.clone(), acp);
    let (created, initial, events) = connection.project(&create).await;
    let session_id = created.root_id.0;
    assert_coverage(&events, session_id, None);
    assert_eq!(initial.workspace_path, workspace.to_string_lossy());
    assert!(initial.history.is_empty());
    connection
        .settle_worker_startup(&ctx, session_id, events)
        .await;
    let tree_seq = ctx
        .db
        .latest_agent_tree_event_seq(session_id)
        .await
        .unwrap()
        .unwrap();
    let persisted_tree: i64 = ctx.db.read(move |conn| {
        Ok(conn.query_row(
            "SELECT count(*) FROM code_root_projection_deliveries WHERE session_id = ?1 AND source_key = ?2",
            rusqlite::params![session_id.to_string(), format!("state:agent_tree:{tree_seq}")],
            |row| row.get(0),
        )?)
    }).await.unwrap();
    assert_eq!(
        persisted_tree, 1,
        "a real committed startup agent-tree transition remains durable"
    );

    // Inverse control: healthy initial receipts keep good text and do not
    // manufacture withholding merely because this is a retry.
    if matches!(route, ReceiptRoute::Create) {
        let (healthy_retry, healthy_root, events) = connection.project(&create).await;
        assert_same_receipt(&created, &healthy_retry, &healthy_root);
        assert_coverage(&events, session_id, None);
        assert_eq!(
            serde_json::to_value(&healthy_root).unwrap(),
            serde_json::to_value(&initial).unwrap()
        );
    }

    ctx.db
        .rename_session(
            session_id,
            &format!("{PUBLIC_TITLE} {OLD_SECRET} {NEW_SECRET}"),
        )
        .await
        .unwrap();
    let frozen_seq = ctx
        .db
        .insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": format!("{PUBLIC_HISTORY} {OLD_SECRET} {NEW_SECRET}")}),
        )
        .await
        .unwrap();

    // Persist real paused state before attaching/recovering a receipt. A
    // create receipt already exists, so its reconnect must hydrate the newer
    // paused row without changing the frozen result or either durable ledger.
    ctx.db
        .upsert_paused_session_work(
            session_id,
            "Build",
            &workspace.to_string_lossy(),
            "daemon restart",
            1,
            proto::DAEMON_VERSION,
        )
        .await
        .unwrap();

    if matches!(route, ReceiptRoute::Attach) {
        let healthy = composed_attach(
            proto::AttachExistingCodeRootV1Request {
                root_id: created.root_id,
                capture_generation: created.capture_generation,
                logical_client_id: base_create.logical_client_id.clone(),
                client_request_id: proto::OpaqueAsciiId128V1::new("healthy-attach-receipt")
                    .unwrap(),
                replay_cursor: Some(created.replay_cursor.clone()),
                since_seq: None,
                options: base_create.options.clone(),
            },
            acp,
        );
        let (healthy_receipt, healthy_root, events) = connection.project(&healthy).await;
        assert_coverage(&events, session_id, None);
        assert_eq!(healthy_root.workspace_path, workspace.to_string_lossy());
        assert!(
            healthy_root
                .title
                .as_deref()
                .unwrap()
                .starts_with(PUBLIC_TITLE)
        );
        assert!(
            matches!(healthy_root.history.as_slice(), [proto::HistoryEntry::User { text, seq, .. }]
            if text.starts_with(PUBLIC_HISTORY) && *seq == frozen_seq)
        );
        assert!(
            !serde_json::to_string(&healthy_root)
                .unwrap()
                .contains(OLD_SECRET)
        );
        let (retry, retry_root, events) = connection.project(&healthy).await;
        assert_same_receipt(&healthy_receipt, &retry, &retry_root);
        assert_coverage(&events, session_id, None);
        assert_eq!(
            serde_json::to_value(&retry_root).unwrap(),
            serde_json::to_value(&healthy_root).unwrap()
        );
    }

    let request = match route {
        ReceiptRoute::Create => create,
        ReceiptRoute::Attach => {
            let base = proto::AttachExistingCodeRootV1Request {
                root_id: created.root_id,
                capture_generation: created.capture_generation,
                logical_client_id: base_create.logical_client_id.clone(),
                client_request_id: proto::OpaqueAsciiId128V1::new("attach-receipt").unwrap(),
                replay_cursor: Some(created.replay_cursor.clone()),
                since_seq: None,
                options: base_create.options.clone(),
            };
            composed_attach(base, acp)
        }
        ReceiptRoute::RecoveredCreate => {
            let mut base = base_create.clone();
            base.client_request_id = proto::OpaqueAsciiId128V1::new("recover-create").unwrap();
            // Model cancellation after worker installation, before the first
            // receipt. The actual recovering dispatcher must finish this root.
            let mut authority = crate::sync::lock_or_recover(&ctx.code_root_authority);
            assert!(matches!(
                authority.start_create(&base).unwrap(),
                crate::daemon::code_roots::CodeRootRequestStart::Started
            ));
            authority
                .bind_created_root(
                    &base.logical_client_id,
                    &base.client_request_id,
                    created.root_id,
                )
                .unwrap();
            authority.abandon_code_root_request(
                &base.logical_client_id,
                &base.client_request_id,
                "create",
            );
            composed_create(base, acp)
        }
    };
    // A sparse over-limit file exercises actual workspace capture without
    // allocating the file's size. Daemon-global coverage scans no workspace.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&dotenv)
        .unwrap()
        .set_len(crate::resource_limits::ResourceLimits::defaults().fs_read_max_file_bytes + 1)
        .unwrap();
    let (receipt, withheld, events) = connection.project(&request).await;
    assert_coverage(
        &events,
        session_id,
        Some(proto::RedactionCoverageFailure::SourceFileOverLimit),
    );
    assert_eq!(withheld.root_id, created.root_id);
    assert_eq!(
        withheld.workspace_path,
        crate::redact::COVERAGE_WITHHELD_PLACEHOLDER
    );
    if !matches!(route, ReceiptRoute::Create) {
        assert_eq!(
            withheld.title.as_deref(),
            Some(crate::redact::COVERAGE_WITHHELD_PLACEHOLDER)
        );
        assert!(
            matches!(withheld.history.as_slice(), [proto::HistoryEntry::User { text, seq, .. }]
            if text == crate::redact::COVERAGE_WITHHELD_PLACEHOLDER && *seq == frozen_seq)
        );
    }
    let deliveries = ctx
        .db
        .read_code_root_projection_deliveries(session_id, None, 256)
        .await
        .unwrap();
    // A newer title/row must never replace the semantic result being retried.
    ctx.db
        .rename_session(session_id, "Later title must not enter the frozen receipt")
        .await
        .unwrap();
    ctx.db
        .insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": LATER_HISTORY}),
        )
        .await
        .unwrap();
    let history_rows = complete_history(&ctx.db, session_id).await;
    let paused_rows = ctx.db.paused_session_work(session_id).await.unwrap();
    assert!(paused_rows.is_some(), "the paused row remains unresolved");

    connection.close().await;

    // Exact logical identity, genuinely new connection and client instance.
    let mut connection = ReceiptConnection::open(&ctx).await;
    let (reconnected, root, events) = connection.project(&request).await;
    assert_same_receipt(&receipt, &reconnected, &root);
    assert!(
        events.iter().any(|event| matches!(event,
            proto::Event::Notice { session_id: id, text }
            if *id == session_id && text.starts_with("paused work is waiting")
        )),
        "reconnect still receives the paused-state reminder"
    );
    assert_coverage(
        &events,
        session_id,
        Some(proto::RedactionCoverageFailure::SourceFileOverLimit),
    );
    assert_eq!(
        serde_json::to_value(&root).unwrap(),
        serde_json::to_value(&withheld).unwrap()
    );

    let (same_connection, root, events) = connection.project(&request).await;
    assert_same_receipt(&reconnected, &same_connection, &root);
    assert_coverage(
        &events,
        session_id,
        Some(proto::RedactionCoverageFailure::SourceFileOverLimit),
    );
    assert_eq!(
        serde_json::to_value(&root).unwrap(),
        serde_json::to_value(&withheld).unwrap()
    );

    // Current projection of the canonical receipt is the defined recovery:
    // no new request identity or transcript read. Retain historical protection
    // for OLD_SECRET and capture NEW_SECRET from the changed file.
    std::fs::write(&dotenv, format!("TOKEN={NEW_SECRET}\n")).unwrap();
    let (recovered, root, events) = connection.project(&request).await;
    assert_same_receipt(&same_connection, &recovered, &root);
    assert_coverage(&events, session_id, None);
    assert_eq!(root.workspace_path, workspace.to_string_lossy());
    if matches!(route, ReceiptRoute::Create) {
        assert_eq!(
            serde_json::to_value(&root).unwrap(),
            serde_json::to_value(&initial).unwrap()
        );
    } else {
        assert!(root.title.as_deref().unwrap().starts_with(PUBLIC_TITLE));
        assert!(
            matches!(root.history.as_slice(), [proto::HistoryEntry::User { text, seq, .. }]
            if text.starts_with(PUBLIC_HISTORY) && *seq == frozen_seq)
        );
    }
    let rendered = serde_json::to_string(&root).unwrap();
    for excluded in [
        OLD_SECRET,
        NEW_SECRET,
        LATER_HISTORY,
        "Later title",
        crate::redact::COVERAGE_WITHHELD_PLACEHOLDER,
    ] {
        assert!(
            !rendered.contains(excluded),
            "recovered frozen projection contains {excluded}"
        );
    }
    assert_eq!(
        ctx.db.list_sessions(false, u32::MAX).await.unwrap().len(),
        1
    );
    assert_eq!(
        complete_history(&ctx.db, session_id).await,
        history_rows,
        "paused-work hydration must preserve complete history rows"
    );
    assert_eq!(
        ctx.db.paused_session_work(session_id).await.unwrap(),
        paused_rows
    );
    assert_eq!(
        ctx.db
            .read_code_root_projection_deliveries(session_id, None, 256)
            .await
            .unwrap(),
        deliveries,
        "replay never mints duplicate durable deliveries"
    );
    crate::sync::lock_or_recover(&ctx.code_root_authority)
        .authenticate(&recovered.attachment_capability)
        .unwrap();
    assert!(
        crate::sync::lock_or_recover(&ctx.code_root_authority)
            .authenticate(&same_connection.attachment_capability)
            .is_err()
    );
    // Inverse: the very same text from a new worker notice remains durable.
    // Publication intent, rather than the Notice variant or its text, decides
    // whether this is hydration or a committed transition.
    let handle = ctx.registry.live_handle(session_id).unwrap();
    handle.broadcast_notice(
        "paused work is waiting for resume or cancel after daemon restart".into(),
    );
    assert_eq!(
        complete_history(&ctx.db, session_id).await.len(),
        history_rows.len() + 1
    );
    assert_eq!(
        ctx.db
            .read_code_root_projection_deliveries(session_id, None, 256)
            .await
            .unwrap()
            .len(),
        deliveries.len() + 1
    );
    for (request, expected_text) in [
        (
            Request::ResumePausedWork { session_id },
            "paused work resumed",
        ),
        (
            Request::CancelPausedWork { session_id },
            "paused work cancelled",
        ),
    ] {
        if matches!(request, Request::CancelPausedWork { .. }) {
            ctx.db
                .upsert_paused_session_work(
                    session_id,
                    "Build",
                    &workspace.to_string_lossy(),
                    "parked again",
                    1,
                    proto::DAEMON_VERSION,
                )
                .await
                .unwrap();
        }
        let before = ctx
            .db
            .read_code_root_projection_deliveries(session_id, None, 256)
            .await
            .unwrap();
        let rows_before = ctx.db.list_session_events(session_id).await.unwrap().len();
        connection.ack(request).await;
        let rows = ctx.db.list_session_events(session_id).await.unwrap();
        assert_eq!(
            rows.len(),
            rows_before + 1,
            "real paused-work changes retain durable notices"
        );
        assert_eq!(rows.last().unwrap().kind, "notice");
        assert!(
            rows.last().unwrap().data["text"]
                .as_str()
                .unwrap()
                .starts_with(expected_text)
        );
        assert!(
            ctx.db
                .paused_session_work(session_id)
                .await
                .unwrap()
                .is_none()
        );
        let after = ctx
            .db
            .read_code_root_projection_deliveries(session_id, None, 256)
            .await
            .unwrap();
        assert_eq!(
            after.len(),
            before.len() + 1,
            "real paused-work changes still invalidate the root"
        );
        assert_eq!(&after[..before.len()], before);
        assert_ne!(
            after.last().unwrap().replay_cursor,
            before.last().unwrap().replay_cursor
        );
    }
    connection.close().await;
    let _ = ctx.registry.drain_all(Duration::ZERO).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn code_root_create_receipt_replay_projects_current_coverage() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    for acp in [false, true] {
        exercise_receipt_projection(ReceiptRoute::Create, acp).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn code_root_attach_receipt_replay_explains_withholding_and_recovers() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    for acp in [false, true] {
        exercise_receipt_projection(ReceiptRoute::Attach, acp).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn code_root_recovered_create_receipt_replay_keeps_canonical_snapshot() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    for acp in [false, true] {
        exercise_receipt_projection(ReceiptRoute::RecoveredCreate, acp).await;
    }
}

/// Compare every stored column, including identities, timestamps and payloads.
async fn complete_history(db: &Db, session_id: Uuid) -> Vec<Vec<rusqlite::types::Value>> {
    db.read(move |conn| {
        let mut stmt =
            conn.prepare("SELECT * FROM session_events WHERE session_id = ?1 ORDER BY seq")?;
        let columns = stmt.column_count();
        let rows = stmt.query_map([session_id.to_string()], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
    .await
    .unwrap()
}

/// Include unkeyed deliveries so restoring the old writer cannot evade the
/// assertion. Other keyed rows are independently committed worker transitions,
/// not the initial operation being cancelled by this fixture.
async fn initial_operation_rows(db: &Db, session_id: Uuid) -> Vec<Vec<rusqlite::types::Value>> {
    db.read(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT * FROM code_root_projection_deliveries WHERE session_id = ?1
             AND (source_key IS NULL OR source_key LIKE 'initial:%') ORDER BY sequence",
        )?;
        let columns = stmt.column_count();
        let rows = stmt.query_map([session_id.to_string()], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
    .await
    .unwrap()
}

async fn exercise_initial_delivery_cancellation(create: bool, acp: bool, accepted: bool) {
    use crate::db::code_root_projection::ProjectionWritePhaseForTest;
    let temp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(temp.path()).unwrap();
    let ctx = disk_test_ctx(&workspace.join("receipt.db"), &workspace.join("spool"));
    ctx.db
        .set_workspace_trust(
            &workspace,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .await
        .unwrap();
    let Request::CreateCodeRootV1(base) = proto::create_code_root_v1_request(
        workspace.to_string_lossy().into_owned(),
        None,
        false,
        true,
        None,
        None,
        proto::EnvDriftPolicy::Daemon,
    ) else {
        panic!("create constructor")
    };
    let mut connection = ReceiptConnection::open(&ctx).await;
    let request = if create {
        composed_create(base.clone(), acp)
    } else {
        let (created, _, events) = connection
            .project(&composed_create(base.clone(), acp))
            .await;
        connection
            .settle_worker_startup(&ctx, created.root_id.0, events)
            .await;
        composed_attach(
            proto::AttachExistingCodeRootV1Request {
                root_id: created.root_id,
                capture_generation: created.capture_generation,
                logical_client_id: base.logical_client_id.clone(),
                client_request_id: proto::OpaqueAsciiId128V1::new("cancelled-initial-attach")
                    .unwrap(),
                replay_cursor: None,
                since_seq: None,
                options: base.options.clone(),
            },
            acp,
        )
    };
    let mut pause = ctx
        .db
        .pause_next_code_root_projection_for_test(if accepted {
            ProjectionWritePhaseForTest::Accepted
        } else {
            ProjectionWritePhaseForTest::BeforeEnqueue
        })
        .unwrap();
    connection
        .client
        .send(&Envelope::request(Uuid::now_v7(), request.clone()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), pause.entered())
        .await
        .expect("initial projection reaches the selected real writer boundary")
        .unwrap();
    // This drops the stream and joins the real transport, which must abort and
    // join its executor while the write is paused. No dispatch future remains.
    connection.close().await;
    let sessions = ctx.db.list_sessions(false, u32::MAX).await.unwrap();
    assert_eq!(
        sessions.len(),
        1,
        "cancelled create has exactly one durable root"
    );
    let session_id = sessions[0].session_id;
    // No response receipt was recorded at either pause. Check the real
    // authority after the transport joined, then relinquish this probe claim.
    {
        use crate::daemon::code_roots::CodeRootRequestStart;
        let mut authority = crate::sync::lock_or_recover(&ctx.code_root_authority);
        if create {
            assert!(
                matches!(authority.start_create(&base).unwrap(), CodeRootRequestStart::Recovering(id) if id.0 == session_id)
            );
            authority.abandon_code_root_request(
                &base.logical_client_id,
                &base.client_request_id,
                "create",
            );
        } else {
            let attach = match &request {
                Request::AttachExistingCodeRootV1(attach) => attach,
                Request::AttachExistingCodeRootWithAcpIngressV1(attach) => &attach.base,
                _ => panic!("attach request"),
            };
            assert!(matches!(
                authority.start_attach(attach).unwrap(),
                CodeRootRequestStart::Started
            ));
            authority.abandon_code_root_request(
                &attach.logical_client_id,
                &attach.client_request_id,
                "attach",
            );
        }
    }
    drop(pause);
    // The FIFO writer barrier drains the accepted job even though its reply
    // receiver was cancelled. Pre-enqueue cancellation has no job to drain.
    ctx.db.write(|_| Ok(())).await.unwrap();
    let before_retry = initial_operation_rows(&ctx.db, session_id).await;
    let preceding_create = usize::from(!create);
    assert_eq!(before_retry.len(), preceding_create + usize::from(accepted));
    let mut connection = ReceiptConnection::open(&ctx).await;
    let (receipt, _, _) = connection.project(&request).await;
    assert_eq!(receipt.root_id.0, session_id);
    let after_retry = initial_operation_rows(&ctx.db, session_id).await;
    assert_eq!(
        after_retry.len(),
        preceding_create + 1,
        "cancel/retry must leave exactly one initial delivery for the logical operation"
    );
    if accepted {
        assert_eq!(
            after_retry, before_retry,
            "accepted delivery identity, cursor and complete row survive cancellation"
        );
    }
    let deliveries = ctx
        .db
        .read_code_root_projection_deliveries(session_id, None, 256)
        .await
        .unwrap();
    let initial_cursor = deliveries
        .iter()
        .find(|row| {
            Some(row.replay_cursor.as_str())
                == after_retry
                    .last()
                    .and_then(|row| row.get(2))
                    .and_then(|v| match v {
                        rusqlite::types::Value::Text(value) => Some(value.as_str()),
                        _ => None,
                    })
        })
        .expect("initial operation cursor resolves in the real ledger");
    assert_eq!(
        receipt.replay_cursor.expose_opaque(),
        initial_cursor.replay_cursor
    );
    let (retry, retry_root, _) = connection.project(&request).await;
    assert_same_receipt(&receipt, &retry, &retry_root);
    assert_eq!(
        initial_operation_rows(&ctx.db, session_id).await,
        after_retry
    );

    // A distinct logical attach must keep its own initial delivery and cursor.
    let distinct = composed_attach(
        proto::AttachExistingCodeRootV1Request {
            root_id: receipt.root_id,
            capture_generation: receipt.capture_generation,
            logical_client_id: base.logical_client_id.clone(),
            client_request_id: proto::OpaqueAsciiId128V1::new("different-attach").unwrap(),
            replay_cursor: None,
            since_seq: None,
            options: base.options,
        },
        acp,
    );
    let (distinct, _, _) = connection.project(&distinct).await;
    assert_ne!(distinct.replay_cursor, receipt.replay_cursor);
    assert_eq!(
        initial_operation_rows(&ctx.db, session_id).await.len(),
        preceding_create + 2,
        "distinct logical operations must not share an initial delivery"
    );
    connection.close().await;
    let _ = ctx.registry.drain_all(Duration::ZERO).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn code_root_create_initial_delivery_survives_accepted_cancel() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    for acp in [false, true] {
        exercise_initial_delivery_cancellation(true, acp, true).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn code_root_attach_initial_delivery_survives_accepted_cancel() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    for acp in [false, true] {
        exercise_initial_delivery_cancellation(false, acp, true).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn code_root_create_initial_delivery_follows_preaccept_cancel() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    for acp in [false, true] {
        exercise_initial_delivery_cancellation(true, acp, false).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn code_root_attach_initial_delivery_follows_preaccept_cancel() {
    let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
    for acp in [false, true] {
        exercise_initial_delivery_cancellation(false, acp, false).await;
    }
}
