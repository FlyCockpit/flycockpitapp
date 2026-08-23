use super::handle::*;
use super::helpers::*;
use super::lifecycle::*;
use super::run::*;
use super::*;

#[test]
fn remote_queue_receipt_is_closed_secret_free_and_consistent() {
    let receipt = RemoteQueueMutationReceiptV1 {
        schema_version: 1,
        applied: true,
        reason: proto::RemoveQueuedUserMessageReason::Removed,
        removed_count: 1,
    };
    receipt.validate().unwrap();
    let applied_wire =
        serde_json::to_vec(&remote_queue_mutation_response(receipt.clone())).unwrap();
    let replay_wire = serde_json::to_vec(&remote_queue_mutation_response(receipt.clone())).unwrap();
    assert_eq!(applied_wire, replay_wire);
    assert!(!String::from_utf8(applied_wire).unwrap().contains("text"));
    let encoded = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(
        serde_json::from_slice::<RemoteQueueMutationReceiptV1>(&encoded).unwrap(),
        receipt
    );
    assert!(!String::from_utf8(encoded).unwrap().contains("text"));
    assert!(
        serde_json::from_str::<RemoteQueueMutationReceiptV1>(
            r#"{"schema_version":1,"applied":true,"reason":"removed","removed_count":1,"text":"secret"}"#
        )
        .is_err()
    );
    assert!(
        RemoteQueueMutationReceiptV1 {
            schema_version: 1,
            applied: false,
            reason: proto::RemoveQueuedUserMessageReason::Removed,
            removed_count: 1,
        }
        .validate()
        .is_err()
    );
    RemoteQueueMutationReceiptV1 {
        schema_version: 1,
        applied: true,
        reason: proto::RemoveQueuedUserMessageReason::Removed,
        removed_count: 2,
    }
    .validate()
    .unwrap();
}

#[tokio::test]
async fn remote_queue_receipt_and_terminal_disposition_commit_and_replay_together() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    let session_id = session.id;
    let submission_id = Uuid::new_v4();
    let operation = || crate::db::remote_attachment_operations::ReserveRemoteOperation {
        logical_attachment_id: "00000000-0000-4000-8000-000000000021",
        operation_id: "01890f3e-4c00-7000-8000-000000000095",
        authenticated_device_id: "00000000-0000-4000-8000-000000000022",
        authenticated_device_generation: 1,
        operation_class:
            crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
        request_hash: [5; 32],
        now_ms: 1,
    };
    let terminal = crate::db::session_log::ClientSubmissionTerminalReceipt {
        client_submission_id: submission_id,
        fingerprint: "fingerprint".into(),
        wire_fingerprint: "wire-fingerprint".into(),
        origin_principal: Some("flycockpit:user".into()),
        disposition: crate::db::session_log::ClientSubmissionTerminalDisposition::Removed,
    };
    let applied = db
        .execute_transactional_remote_operation(operation(), move |conn| {
            crate::db::Db::insert_client_submission_terminal_receipts_conn(
                conn,
                session_id,
                &[terminal],
            )?;
            let receipt = RemoteQueueMutationReceiptV1 {
                schema_version: 1,
                applied: true,
                reason: proto::RemoveQueuedUserMessageReason::Removed,
                removed_count: 1,
            };
            let safe_response = serde_json::to_vec(&receipt)?;
            Ok(
                crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                    value: receipt,
                    safe_response: safe_response.clone(),
                    outbox_kind: "remove_queued_user_message".into(),
                    outbox_payload: safe_response,
                },
            )
        })
        .await
        .unwrap();
    assert!(matches!(
        applied,
        crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(_)
    ));
    assert!(
        db.client_submission_terminal_receipt(session_id, submission_id)
            .await
            .unwrap()
            .is_some()
    );
    let replay: crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome<
        RemoteQueueMutationReceiptV1,
    > = db
        .execute_transactional_remote_operation(operation(), |_| {
            panic!("replay must not rewrite terminal receipt")
        })
        .await
        .unwrap();
    let crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) =
        replay
    else {
        panic!("expected replay")
    };
    assert_eq!(
        serde_json::from_slice::<RemoteQueueMutationReceiptV1>(&bytes)
            .unwrap()
            .removed_count,
        1
    );
}
use crate::db::Db;
use std::io;
use std::sync::Mutex as StdMutex;
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

#[tokio::test]
async fn paste_fence_model_switch_ordering_change_before_and_after_acceptance() {
    let selection = cockpit_config::providers::ActiveModelRef {
        provider: "provider-a".to_string(),
        model: "model-a".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    let current = proto::ActiveModelState {
        selection: selection.clone(),
        default_selection: None,
        diverged: false,
        generation: 7,
    };
    assert!(model_expectation_matches(Some(&current), 7, &selection));

    let mut changed = current.clone();
    changed.generation = 8;
    assert!(!model_expectation_matches(Some(&changed), 7, &selection));
    assert!(!model_expectation_matches(None, 7, &selection));

    let (updates, _updates_rx) = watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates);
    let id = Uuid::new_v4();
    let submission = crate::engine::message::UserSubmission::text("captured payload");
    let receipt = crate::engine::message::ClientSubmissionReceipt {
        id,
        fingerprint: submission.client_fingerprint(),
        wire_fingerprint: "wire-v1".to_string(),
        origin_principal: None,
    };
    queue
        .push_idempotent(
            receipt,
            submission,
            crate::engine::message::QueueTarget::root("Build"),
        )
        .await;
    let accepted = queue.has_accepted(id).await;
    assert!(accepted);
    assert!(model_fence_allows_insert(
        accepted,
        Some(&changed),
        7,
        &selection
    ));
    assert!(!model_fence_allows_insert(
        false,
        Some(&changed),
        7,
        &selection
    ));
}

fn trusted_test_policy(root: &std::path::Path) -> crate::config::trust::WorkspaceTrustPolicy {
    crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::TrustRoot {
            opened_path: root.to_path_buf(),
            root: root.to_path_buf(),
            kind: crate::config::trust::TrustRootKind::Directory,
        },
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    }
}

#[derive(Clone)]
struct CaptureWriter(Arc<StdMutex<Vec<u8>>>);

struct CaptureGuard(Arc<StdMutex<Vec<u8>>>);

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

fn capture_warn_log<T>(f: impl FnOnce() -> T) -> (T, String) {
    let bytes = Arc::new(StdMutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::WARN)
        .with_ansi(false)
        .with_writer(CaptureWriter(bytes.clone()))
        .finish();
    let result = tracing::subscriber::with_default(subscriber, f);
    (
        result,
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap(),
    )
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

fn test_session_handle() -> SessionWorkerHandle {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    let locks = Arc::new(LockManager::in_memory(db));
    SessionWorkerHandle::test_handle(session, locks)
}

#[tokio::test]
async fn terminal_receipt_write_failure_returns_promptly_and_holds_the_exact_queue_item() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    db.write(|conn| {
        conn.execute_batch(
            "CREATE TRIGGER fail_terminal_receipt
             BEFORE INSERT ON client_submission_terminal_receipts
             BEGIN
               SELECT RAISE(FAIL, 'injected persistent terminal receipt failure');
             END;",
        )?;
        Ok(())
    })
    .await
    .unwrap();

    let (updates_tx, _updates_rx) = watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let target = crate::engine::message::QueueTarget::root("Build");
    let id = Uuid::new_v4();
    let receipt = crate::engine::message::ClientSubmissionReceipt {
        id,
        fingerprint: "consumed-fingerprint".into(),
        wire_fingerprint: "wire-fingerprint".into(),
        origin_principal: Some("flycockpit:user-1".into()),
    };
    let expected_receipt = receipt.clone();
    let original = crate::engine::message::UserSubmission {
        text: "exact wire text".into(),
        display_text: Some("visible composer text".into()),
        images: vec![vec![7, 8, 9]],
        forced_skill: Some("review".into()),
        origin_principal: receipt.origin_principal.clone(),
        queue_item_ids: vec![id],
        client_submissions: vec![receipt.clone()],
        queue_target: Some(target.clone()),
        ..Default::default()
    };
    let (_, _, inserted) = queue
        .push_idempotent(receipt, original.clone(), target)
        .await;
    assert_eq!(inserted, crate::engine::message::IdempotentPush::Inserted);
    let (_, staged, _) = queue.stage_remove(id).await.unwrap();

    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        persist_staged_terminal_removal(
            &session,
            &queue,
            staged.expect("queued item is staged"),
            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed,
        ),
    )
    .await
    .expect("a persistent receipt failure must not monopolize the worker")
    .expect_err("injected trigger rejects the terminal receipt");
    assert_eq!(error.code, proto::ErrorCode::Internal);
    assert!(error.message.contains("remains held"), "{}", error.message);
    assert_eq!(
        queue
            .snapshot()
            .await
            .iter()
            .map(|item| item.id)
            .collect::<Vec<_>>(),
        vec![id],
        "the failed removal keeps the exact item visible while holding execution"
    );
    assert_eq!(
        serde_json::to_value(queue.pending_submission(id).await.unwrap()).unwrap(),
        serde_json::to_value(original).unwrap(),
        "the failure hold retains the complete wire payload"
    );
    assert_eq!(
        queue.accepted_receipts(&[id]).await,
        vec![expected_receipt],
        "the failure hold retains the exact idempotency receipt for a safe retry"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv())
            .await
            .is_err(),
        "a persistent receipt failure must not release the payload into execution"
    );

    let (_, staged, _) = queue
        .stage_remove(id)
        .await
        .expect("the same removal can retry its held claim");
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        persist_staged_terminal_removal(
            &session,
            &queue,
            staged.expect("held removal returns its original claim"),
            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed,
        ),
    )
    .await
    .expect("a repeated persistent failure remains prompt")
    .expect_err("the trigger remains active for the first retry");

    db.write(|conn| {
        conn.execute_batch("DROP TRIGGER fail_terminal_receipt;")?;
        Ok(())
    })
    .await
    .unwrap();
    let (_, staged, _) = queue.stage_remove(id).await.unwrap();
    let (removed, snapshot, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        persist_staged_terminal_removal(
            &session,
            &queue,
            staged.expect("held item can be removed again"),
            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed,
        ),
    )
    .await
    .expect("subsequent worker work remains serviceable")
    .expect("receipt write succeeds after the injected failure is removed");
    assert_eq!(
        removed.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![id]
    );
    assert!(snapshot.is_empty());
    assert!(
        db.client_submission_terminal_receipt(session.id, id)
            .await
            .unwrap()
            .is_some(),
        "the retry commits the durable terminal receipt"
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), queue.close())
        .await
        .expect("queue shutdown remains serviceable after the failed receipt write");
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), queue.recv())
            .await
            .expect("closed held queue receiver exits promptly")
            .is_none()
    );
}

#[test]
fn live_worker_persistent_terminal_failure_holds_fifo_and_shuts_down() {
    crate::test_env::run_async_with_large_stack(|| async {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        // Production workers boot with a daemon-owned journal installed; the
        // barrier is non-optional, so mirror that for this live-worker test.
        session.install_test_external_journal();
        session
            .set_active_model("lmstudio", "session-model")
            .unwrap();
        db.write(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_terminal_receipt_live_worker
             BEFORE INSERT ON client_submission_terminal_receipts
             BEGIN
               SELECT RAISE(FAIL, 'injected persistent live-worker terminal receipt failure');
             END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider_server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let mut providers = lmstudio_test_providers();
        providers.providers.get_mut("lmstudio").unwrap().url = format!("http://{address}/v1");
        let redact = Arc::new(RedactionTable::empty());
        let model =
            Arc::new(crate::engine::model::Model::from_config(&providers, redact.clone()).unwrap());
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended.sandbox.default_mode = crate::config::sandbox_mode::SandboxMode::Off;
        let (handle, join) = spawn(
            session.clone(),
            Arc::new(LockManager::in_memory(db.clone())),
            redact,
            model,
            None,
            None,
            None,
            tmp.path().to_path_buf(),
            false,
            false,
            &extended,
            Arc::new(crate::daemon::lsp::LspManager::new()),
            None,
            Arc::new(StdMutex::new(None)),
            Arc::new(StdMutex::new(None)),
            None,
            trusted_test_policy(tmp.path()),
            None,
            EnvSnapshot::new(
                crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                Default::default(),
            ),
            SessionConfigSnapshot::new(0, providers, extended.clone()),
        );
        let mut events = handle.subscribe();

        async fn enqueue(
            handle: &SessionWorkerHandle,
            mut submission: crate::engine::message::UserSubmission,
        ) -> (Uuid, Vec<proto::QueueItem>) {
            let id = Uuid::new_v4();
            let fingerprint = submission.client_fingerprint();
            submission.queue_item_ids = vec![id];
            submission.client_submissions = vec![crate::engine::message::ClientSubmissionReceipt {
                id,
                fingerprint: fingerprint.clone(),
                wire_fingerprint: format!("wire-{fingerprint}"),
                origin_principal: submission.origin_principal.clone(),
            }];
            let (respond_to, response) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::UserMessage {
                    submission: Box::new(submission),
                    remote_operation: None,
                    respond_to,
                })
                .await
                .unwrap();
            let (item, queue) = tokio::time::timeout(std::time::Duration::from_secs(2), response)
                .await
                .expect("live worker acknowledges accepted message")
                .expect("worker response channel remains open")
                .expect("message is accepted");
            assert_eq!(item.id, id);
            (id, queue)
        }

        let _ = enqueue(
            &handle,
            crate::engine::message::UserSubmission::text("active blocking turn"),
        )
        .await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if matches!(
                    events.recv().await.unwrap().event,
                    proto::Event::ThinkingStarted { .. }
                ) {
                    break;
                }
            }
        })
        .await
        .expect("the first message reaches the live driver");

        let second = crate::engine::message::UserSubmission {
            text: "second exact wire text".into(),
            display_text: Some("second visible text".into()),
            images: vec![vec![1, 2, 3, 4]],
            forced_skill: Some("review".into()),
            origin_principal: Some("flycockpit:user-1".into()),
            ..Default::default()
        };
        let (second_id, _) = enqueue(&handle, second).await;
        let (third_id, queue) = enqueue(
            &handle,
            crate::engine::message::UserSubmission::text("third queued message"),
        )
        .await;
        assert_eq!(
            queue.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![second_id, third_id],
            "the live driver leaves the later submissions in FIFO order"
        );

        let operation = RemoteQueueOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000031".into(),
            operation_id: "01890f3e-4c00-7000-8000-000000000094".into(),
            authenticated_device_id: "00000000-0000-4000-8000-000000000032".into(),
            authenticated_device_generation: 1,
            request_hash: [4; 32],
        };
        async fn remove_exact(
            handle: &SessionWorkerHandle,
            id: Uuid,
            operation: Option<RemoteQueueOperation>,
        ) -> Result<proto::RemoveQueuedUserMessageResult, proto::ErrorPayload> {
            let (respond_to, response) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::RemoveQueuedUserMessage {
                    queue_item_id: id,
                    remote_operation: operation,
                    respond_to,
                })
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), response)
                .await
                .expect("persistent receipt failure returns promptly")
                .expect("removal response channel remains open")
        }

        for _ in 0..2 {
            let error = remove_exact(&handle, second_id, Some(operation.clone()))
                .await
                .expect_err("the active trigger rejects the atomic queue commit");
            assert_eq!(error.code, proto::ErrorCode::Internal);
            assert!(
                error.message.contains("could not be committed"),
                "{}",
                error.message
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let user_messages = db
            .list_session_events(session.id)
            .await
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == "user_message")
            .count();
        assert_eq!(
            user_messages, 1,
            "held second and third payloads cannot race into the live driver"
        );
        assert!(
            db.client_submission_terminal_receipt(session.id, second_id)
                .await
                .unwrap()
                .is_none()
        );

        db.write(|conn| {
            conn.execute_batch("DROP TRIGGER fail_terminal_receipt_live_worker;")?;
            Ok(())
        })
        .await
        .unwrap();
        let applied = remove_exact(&handle, second_id, Some(operation.clone()))
            .await
            .unwrap();
        assert!(applied.applied);
        assert!(applied.queue.is_empty());
        let (_fourth_id, _) = enqueue(
            &handle,
            crate::engine::message::UserSubmission::text("later mutable queue state"),
        )
        .await;
        let replay = remove_exact(&handle, second_id, Some(operation.clone()))
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&replay).unwrap(),
            serde_json::to_vec(&applied).unwrap()
        );

        let mut changed = operation;
        changed.request_hash = [3; 32];
        let conflict = remove_exact(&handle, third_id, Some(changed))
            .await
            .unwrap_err();
        assert_eq!(conflict.code, proto::ErrorCode::Conflict);
        let released = remove_exact(&handle, third_id, None).await.unwrap();
        assert!(
            released.applied,
            "conflict must release the staged queue claim"
        );

        async fn remove_newest(
            handle: &SessionWorkerHandle,
            operation: RemoteQueueOperation,
        ) -> Result<proto::RemoveQueuedUserMessageResult, proto::ErrorPayload> {
            let (respond_to, response) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::RemoveNewestQueuedUserMessage {
                    target_id: Some("root".into()),
                    remote_operation: Some(operation),
                    respond_to,
                })
                .await
                .unwrap();
            response.await.unwrap()
        }
        let newest_operation = RemoteQueueOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000031".into(),
            operation_id: "01890f3e-4c00-7000-8000-000000000093".into(),
            authenticated_device_id: "00000000-0000-4000-8000-000000000032".into(),
            authenticated_device_generation: 1,
            request_hash: [2; 32],
        };
        let newest = remove_newest(&handle, newest_operation.clone())
            .await
            .unwrap();
        assert!(newest.applied && newest.queue.is_empty() && newest.removed_item.is_none());
        let newest_replay = remove_newest(&handle, newest_operation).await.unwrap();
        assert_eq!(
            serde_json::to_vec(&newest).unwrap(),
            serde_json::to_vec(&newest_replay).unwrap()
        );

        let _ = enqueue(
            &handle,
            crate::engine::message::UserSubmission::text("editable one"),
        )
        .await;
        let _ = enqueue(
            &handle,
            crate::engine::message::UserSubmission::text("editable two"),
        )
        .await;
        async fn remove_editable(
            handle: &SessionWorkerHandle,
            operation: RemoteQueueOperation,
        ) -> Result<proto::RemoveQueuedUserMessagesResult, proto::ErrorPayload> {
            let (respond_to, response) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::RemoveEditableQueuedUserMessages {
                    target_id: Some("root".into()),
                    remote_operation: Some(operation),
                    respond_to,
                })
                .await
                .unwrap();
            response.await.unwrap()
        }
        let editable_operation = RemoteQueueOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000031".into(),
            operation_id: "01890f3e-4c00-7000-8000-000000000092".into(),
            authenticated_device_id: "00000000-0000-4000-8000-000000000032".into(),
            authenticated_device_generation: 1,
            request_hash: [1; 32],
        };
        let editable = remove_editable(&handle, editable_operation.clone())
            .await
            .unwrap();
        assert!(editable.applied && editable.queue.is_empty() && editable.removed_items.is_empty());
        let editable_replay = remove_editable(&handle, editable_operation).await.unwrap();
        assert_eq!(
            serde_json::to_vec(&editable).unwrap(),
            serde_json::to_vec(&editable_replay).unwrap()
        );

        handle.send_work(SessionWork::Cancel).await.unwrap();
        handle
            .send_work(SessionWork::Shutdown {
                pause_for_resume: false,
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), join)
            .await
            .expect("persistent receipt failure cannot monopolize worker shutdown")
            .expect("live worker does not panic");
        provider_server.abort();
    });
}

/// A `send_user_message` admitted as an authenticated remote operation commits
/// the transactional remote-operation ledger on the REAL worker ACCEPT path
/// (`SessionWork::UserMessage`), not a dispatch-arm shim. A replayed operation
/// identity is a durable no-op (the ledger row stays committed and the message
/// is not accepted a second time).
#[test]
fn send_user_message_remote_path_commits_transactional_ledger() {
    crate::test_env::run_async_with_large_stack(|| async {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        session.install_test_external_journal();
        session
            .set_active_model("lmstudio", "session-model")
            .unwrap();

        // A parked provider socket: the message is ACCEPTED (and ledgered) before
        // the driver ever reaches the model, so the model never has to respond.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider_server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let mut providers = lmstudio_test_providers();
        providers.providers.get_mut("lmstudio").unwrap().url = format!("http://{address}/v1");
        let redact = Arc::new(RedactionTable::empty());
        let model =
            Arc::new(crate::engine::model::Model::from_config(&providers, redact.clone()).unwrap());
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended.sandbox.default_mode = crate::config::sandbox_mode::SandboxMode::Off;
        let (handle, join) = spawn(
            session.clone(),
            Arc::new(LockManager::in_memory(db.clone())),
            redact,
            model,
            None,
            None,
            None,
            tmp.path().to_path_buf(),
            false,
            false,
            &extended,
            Arc::new(crate::daemon::lsp::LspManager::new()),
            None,
            Arc::new(StdMutex::new(None)),
            Arc::new(StdMutex::new(None)),
            None,
            trusted_test_policy(tmp.path()),
            None,
            EnvSnapshot::new(
                crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                Default::default(),
            ),
            SessionConfigSnapshot::new(0, providers, extended.clone()),
        );

        let operation = RemoteQueueOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000051".into(),
            operation_id: "01890f3e-4c00-7000-8000-0000000000b1".into(),
            authenticated_device_id: "00000000-0000-4000-8000-000000000052".into(),
            authenticated_device_generation: 1,
            request_hash: [9; 32],
        };

        async fn send_remote(
            handle: &SessionWorkerHandle,
            client_submission_id: Uuid,
            text: &str,
            operation: RemoteQueueOperation,
        ) -> std::result::Result<(proto::QueueItem, Vec<proto::QueueItem>), proto::ErrorPayload>
        {
            let mut submission = crate::engine::message::UserSubmission::text(text);
            let fingerprint = submission.client_fingerprint();
            submission.queue_item_ids = vec![client_submission_id];
            submission.client_submissions = vec![crate::engine::message::ClientSubmissionReceipt {
                id: client_submission_id,
                fingerprint: fingerprint.clone(),
                wire_fingerprint: format!("wire-{fingerprint}"),
                origin_principal: submission.origin_principal.clone(),
            }];
            let (respond_to, response) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::UserMessage {
                    submission: Box::new(submission),
                    remote_operation: Some(operation),
                    respond_to,
                })
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2), response)
                .await
                .expect("worker acknowledges the remote accept")
                .expect("worker response channel remains open")
        }

        let client_submission_id = Uuid::new_v4();
        let (item, _queue) = send_remote(
            &handle,
            client_submission_id,
            "remote transactional hello",
            operation.clone(),
        )
        .await
        .expect("remote send is accepted on the worker path");
        assert_eq!(item.id, client_submission_id);

        // The accept committed the transactional remote-operation ledger.
        let status = db
            .remote_operation_status(&operation.logical_attachment_id, &operation.operation_id)
            .await
            .unwrap()
            .expect("remote send must reserve a committed transactional ledger row");
        assert_eq!(status.state, "committed");

        // Replay under the same operation identity: still accepted, still exactly
        // one committed ledger row (no second commit / no double accept).
        let (replay_item, _) = send_remote(
            &handle,
            client_submission_id,
            "remote transactional hello",
            operation.clone(),
        )
        .await
        .expect("replayed remote send is idempotent");
        assert_eq!(replay_item.id, client_submission_id);
        let replay_status = db
            .remote_operation_status(&operation.logical_attachment_id, &operation.operation_id)
            .await
            .unwrap()
            .expect("the replayed operation keeps its committed ledger row");
        assert_eq!(replay_status.state, "committed");

        // #2: a CONFLICTING send (same client_submission_id, DIFFERENT content)
        // under a fresh operation identity is rejected by the in-memory dedup
        // decision BEFORE any ledger reservation, so the conflicting operation
        // commits NO ledger row (the acceptance decision precedes the commit).
        let conflict_operation = RemoteQueueOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000061".into(),
            operation_id: "01890f3e-4c00-7000-8000-0000000000c1".into(),
            authenticated_device_id: "00000000-0000-4000-8000-000000000062".into(),
            authenticated_device_generation: 1,
            request_hash: [11; 32],
        };
        let conflict = send_remote(
            &handle,
            client_submission_id,
            "a different payload under the same id",
            conflict_operation.clone(),
        )
        .await;
        assert!(
            conflict.is_err(),
            "a same-id different-content send must be rejected, not accepted"
        );
        assert!(
            db.remote_operation_status(
                &conflict_operation.logical_attachment_id,
                &conflict_operation.operation_id,
            )
            .await
            .unwrap()
            .is_none(),
            "a rejected conflicting send must reserve NO transactional ledger row"
        );

        handle.send_work(SessionWork::Cancel).await.unwrap();
        handle
            .send_work(SessionWork::Shutdown {
                pause_for_resume: false,
            })
            .await
            .unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), join).await;
        provider_server.abort();
    });
}

/// The worker deletes a *scoped* sealed value completely, on behalf of the
/// daemon's `owner_only` `DeleteSealedValue` request.
///
/// A session-scope scoped value is dual-written — the record in
/// `sealed_value_records`, the literal in the legacy `sealed_values` table —
/// so this seeds it through the scoped create and then checks *both* stores
/// plus the name tombstone. An earlier version of this test seeded only a
/// legacy row and asserted only through the legacy existence check, which is
/// why it passed identically while the delete was silently leaving the scoped
/// record behind, resolvable with no literal under it.
#[tokio::test]
async fn worker_delete_removes_the_scoped_sealed_value_completely() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    let scope_key = session.id.to_string();

    db.create_session_sealed_value(
        cockpit_db::db::sealed_scope::NewSealedValueRecord {
            record_id: uuid::Uuid::new_v4().to_string(),
            scope: cockpit_db::db::sealed_scope::SealedScopeKind::Session,
            scope_key: scope_key.clone(),
            name: "prod_token".to_string(),
            description: "deployment credential".to_string(),
            owner_principal: "owner".to_string(),
            created_at_ms: 1_000,
        },
        "very-high-entropy-token".to_string(),
        "deploy".to_string(),
        "user".to_string(),
    )
    .await
    .unwrap();

    let owner = crate::sealed::OwnerAuthority::for_test("owner");
    let inventory = |db: Db, key: String| async move {
        db.sealed_value_inventory(cockpit_db::db::sealed_scope::SealedScopeKind::Session, key)
            .await
            .unwrap()
    };
    assert!(
        session
            .sealed_value_exists(owner, "prod_token")
            .await
            .unwrap()
    );
    assert_eq!(
        inventory(db.clone(), scope_key.clone()).await.len(),
        1,
        "the scoped record exists before the delete"
    );

    let handle = SessionWorkerHandle::test_handle(
        session.clone(),
        Arc::new(LockManager::in_memory(db.clone())),
    );
    assert!(handle.delete_sealed_value("prod_token").await.unwrap());

    assert!(
        !session
            .sealed_value_exists(owner, "prod_token")
            .await
            .unwrap(),
        "the literal is gone"
    );
    assert!(
        inventory(db.clone(), scope_key.clone()).await.is_empty(),
        "the scoped record must go too, not just the legacy literal row"
    );
    assert!(
        db.sealed_value_name_retired(
            cockpit_db::db::sealed_scope::SealedScopeKind::Session,
            scope_key,
            "prod_token".to_string(),
        )
        .await
        .unwrap(),
        "a completed delete retires the name so it is never reused"
    );
}

/// Source-level lint: the retired worker sealed methods must not grow back.
///
/// Scope, stated honestly. That these methods are *absent today* is enforced
/// by the compiler — nothing can call a method that does not exist. What the
/// compiler cannot catch is someone **re-adding** one later, which is the
/// actual regression risk, since their callers (the agent-facing Monty
/// builtins and the `sealed_fetch` delegation mode) were the half-done
/// removal this batch already had to finish once.
///
/// So this is a lint, not a behavioural proof. It matches on bare `fn <name>`
/// rather than a full signature, so a visibility change, an `async` change,
/// or rustfmt splitting the line cannot slip past it — the earlier version of
/// this test pinned exact `pub async fn …` strings and would have missed all
/// three. It also drops a needle (`sealed_values:`) that could never have
/// matched the regression it named.
#[test]
fn worker_sealed_create_and_existence_methods_do_not_grow_back() {
    let source = include_str!("handle.rs");
    let production = source
        .split("\n#[cfg(test)]")
        .next()
        .expect("production module precedes any test module");
    // Normalize so line breaks and repeated spaces cannot hide a match.
    let normalized = production.split_whitespace().collect::<Vec<_>>().join(" ");
    for retired in [
        "fn set_sealed_value",
        "fn sealed_value_exists",
        "fn seal_redaction_literal",
    ] {
        assert!(
            !normalized.contains(retired),
            "the retired worker sealed surface `{retired}` must not return; \
             sealed writes and existence probes belong to the Owner-only \
             scoped path, not to an agent-reachable worker method"
        );
    }
    // The in-memory injection cache is gone with them: it was the thing that
    // made an existence probe cheap enough to be an oracle.
    assert!(
        !normalized.contains("sealed_values :") && !normalized.contains("sealed_values:"),
        "the worker must not carry an in-memory sealed value cache"
    );
}

fn queued_user_message_for_test(text: &str) -> crate::engine::message::QueuedUserMessage {
    crate::engine::message::QueuedUserMessage {
        id: Uuid::new_v4(),
        status: crate::engine::message::QueueItemStatus::Queued,
        text: text.to_string(),
        display_text: None,
        target: crate::engine::message::QueueTarget::root("Build"),
    }
}

async fn recv_queue_updated_for_test(event_rx: &mut EventReceiver) -> Vec<proto::QueueItem> {
    match tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
        .await
        .expect("queue update timed out")
        .expect("queue update event")
        .event
    {
        proto::Event::QueueUpdated { queue, .. } => queue,
        other => panic!("expected QueueUpdated, got {other:?}"),
    }
}

#[tokio::test]
async fn queue_updated_is_not_emitted_for_the_initial_empty_snapshot() {
    let session_id = Uuid::new_v4();
    let (updates_tx, updates_rx) = watch::channel(Vec::new());
    let (event_tx, mut event_rx) = broadcast::channel(8);
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
    let forward = tokio::spawn(forward_queue_updates(
        updates_rx, event_tx, redaction, session_id,
    ));

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), event_rx.recv())
            .await
            .is_err(),
        "initial watch value must not emit QueueUpdated"
    );

    updates_tx
        .send(vec![queued_user_message_for_test("real enqueue")])
        .unwrap();
    let queue = recv_queue_updated_for_test(&mut event_rx).await;
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].text, "real enqueue");

    drop(updates_tx);
    forward.await.unwrap();
}

#[tokio::test]
async fn queue_updated_is_still_emitted_when_the_queue_is_emptied() {
    let session_id = Uuid::new_v4();
    let (updates_tx, updates_rx) = watch::channel(Vec::new());
    let (event_tx, mut event_rx) = broadcast::channel(8);
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
    let forward = tokio::spawn(forward_queue_updates(
        updates_rx, event_tx, redaction, session_id,
    ));

    updates_tx
        .send(vec![queued_user_message_for_test("queued")])
        .unwrap();
    let queue = recv_queue_updated_for_test(&mut event_rx).await;
    assert_eq!(queue.len(), 1);

    updates_tx.send(Vec::new()).unwrap();
    let queue = recv_queue_updated_for_test(&mut event_rx).await;
    assert!(queue.is_empty());

    drop(updates_tx);
    forward.await.unwrap();
}

#[tokio::test]
async fn turn_completion_is_delivered_through_the_lossless_channel() {
    let handle = test_session_handle();
    let completion = handle.watch_turn("turn-1");

    handle.observe_turn_terminal_event_for_test(&proto::Event::AgentIdle {
        session_id: handle.session_id,
        turn_id: Some("turn-1".to_string()),
        reason: crate::engine::IdleReason::Completed,
    });

    assert!(matches!(
        completion.await.unwrap(),
        TurnOutcome::Completed {
            reason: crate::engine::IdleReason::Completed
        }
    ));
}

#[tokio::test]
async fn turn_completion_resolves_when_the_turn_finished_before_the_watcher_registered() {
    let handle = test_session_handle();

    handle.observe_turn_terminal_event_for_test(&proto::Event::AgentIdle {
        session_id: handle.session_id,
        turn_id: Some("turn-before-watch".to_string()),
        reason: crate::engine::IdleReason::GoalComplete,
    });
    let completion = handle.watch_turn("turn-before-watch");

    assert!(matches!(
        completion.await.unwrap(),
        TurnOutcome::Completed {
            reason: crate::engine::IdleReason::GoalComplete
        }
    ));
}

#[tokio::test]
async fn turn_completion_watcher_after_forwarder_close_resolves_closed() {
    let handle = test_session_handle();

    handle.close_turn_completions_for_test();
    let completion = handle.watch_turn("late-turn");

    assert!(completion.await.is_err());
}

#[tokio::test]
async fn stream_delta_coalescer_merges_rapid_consecutive_text() {
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

#[tokio::test]
async fn stream_delta_coalescer_flushes_before_non_delta_event() {
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

#[tokio::test]
async fn stream_delta_coalescer_keeps_agents_and_delta_kinds_separate() {
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

#[tokio::test]
async fn stream_delta_coalescer_byte_cap_flushes_before_window() {
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

#[tokio::test]
async fn stream_delta_coalescer_sets_flush_deadline_only_while_buffered() {
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

#[tokio::test]
async fn steer_side_channel_stores_raw_and_stamps_origin() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
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
        .await
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
    )
    .await;

    assert_eq!(result.status, proto::DelegationSteerStatus::Queued);
    assert_eq!(result.origin_principal.as_deref(), Some("local:tester"));
    assert!(result.scrubbed);
    let steers = session
        .db
        .drain_task_delegation_steers("task-live", "alpha")
        .await
        .unwrap();
    assert_eq!(steers.len(), 1);
    assert_eq!(steers[0].origin_principal, "local:tester");
    assert!(steers[0].body.contains("secret-user-steer-token"));
}

#[tokio::test]
async fn steer_side_channel_rejects_non_running_child_without_enqueue() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
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
        .await
        .unwrap();
    session
        .db
        .cancel_task_delegation_child("task-done", "default")
        .await
        .unwrap();

    let result = steer_delegation_side_channel(
        &session,
        &RedactionTable::empty(),
        "task-done".to_string(),
        "default".to_string(),
        "continue".to_string(),
        "local:tester".to_string(),
    )
    .await;

    assert_eq!(result.status, proto::DelegationSteerStatus::NotSteerable);
    assert!(result.message.contains("cancelled"), "{result:?}");
    assert!(
        session
            .db
            .drain_task_delegation_steers("task-done", "default")
            .await
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
    let session = Session::create_for_test(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    let (event_tx, _event_rx) = broadcast::channel(8);
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
    let (driver_tx, mut driver_rx) = mpsc::channel(1);
    let mut notified = HashSet::new();

    crate::config::trust::scope_workspace_trust_policy(
        trusted_test_policy(tmp.path()),
        refresh_redaction_for_turn(
            &session,
            session.id,
            tmp.path(),
            crate::config::extended::RedactConfig::default(),
            &RedactionSourceOverrides::default(),
            &mut notified,
            &redaction,
            &crate::engine::interrupt::InterruptHub::detached(),
            &event_tx,
            &driver_tx,
            &HashMap::new(),
        ),
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
    assert_eq!(
        persisted.scrub("worker-secret"),
        "worker-secret",
        "dotenv-derived secret values must not be persisted"
    );
    assert!(
        session
            .persisted_disk_redaction_origins()
            .unwrap()
            .iter()
            .any(|origin| origin.contains(".env")),
        "the safe source marker should remain available for resume warnings"
    );
}

async fn persisted_notice_text(session: &Session) -> String {
    let events = session.db.list_session_events(session.id).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "notice");
    events[0].data["text"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn engine_notice_is_recorded_as_durable_session_event() {
    let session = Session::create_for_test(
        Db::open_in_memory().unwrap(),
        PathBuf::from("/proj"),
        "Build",
        crate::session::test_redaction_key_resolver(),
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

    let rows = session.db.list_session_events(session.id).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "notice");
    assert_eq!(rows[0].data["text"], "Engine notice text.");
    assert_eq!(rows[0].data["source"], "engine_turn");
    assert_eq!(rows[0].data["severity"], "info");
}

#[tokio::test]
async fn notice_is_recorded_exactly_once_across_both_paths() {
    let session = Session::create_for_test(
        Db::open_in_memory().unwrap(),
        PathBuf::from("/proj"),
        "Build",
        crate::session::test_redaction_key_resolver(),
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

    let rows = session.db.list_session_events(session.id).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "notice");
    assert_eq!(rows[0].data["text"], "Single notice.");
}

#[tokio::test]
async fn daemon_direct_notice_is_recorded_as_durable_session_event() {
    let session = Session::create_for_test(
        Db::open_in_memory().unwrap(),
        PathBuf::from("/proj"),
        "Build",
        crate::session::test_redaction_key_resolver(),
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

    let rows = session.db.list_session_events(session.id).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "notice");
    assert_eq!(rows[0].data["text"], "Daemon warning.");
    assert_eq!(rows[0].data["source"], "daemon_direct");
    assert_eq!(rows[0].data["severity"], "warning");
}

#[tokio::test]
async fn sessionless_notice_is_dropped_without_error() {
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

#[tokio::test]
async fn recorded_notice_text_is_redacted() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = crate::config::extended::RedactConfig {
        denylist: vec!["session-secret-token".to_string()],
        ..Default::default()
    };
    let table = Arc::new(RedactionTable::build(&cfg, tmp.path()).unwrap());
    let session = Session::create_for_test(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
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

    let text = persisted_notice_text(&session).await;
    assert!(!text.contains("session-secret-token"));
    assert!(text.contains("REDACTED"));
}

#[tokio::test]
async fn session_driver_failed_event_is_latched() {
    let (event_tx, mut event_rx) = broadcast::channel(8);
    let completions = Arc::new(Mutex::new(TurnCompletions::default()));
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
    let session_id = Uuid::new_v4();
    let mut driver_failed = false;
    let mut first_watcher = completions.lock().unwrap().watch("first-turn");
    let mut second_watcher = completions.lock().unwrap().watch("second-turn");

    emit_session_driver_failed_once(
        &event_tx,
        &completions,
        &redaction,
        session_id,
        &mut driver_failed,
        "first failure".to_string(),
    );
    emit_session_driver_failed_once(
        &event_tx,
        &completions,
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
    assert!(matches!(
        first_watcher.try_recv().unwrap(),
        TurnOutcome::Failed { error } if error == "first failure"
    ));
    assert!(matches!(
        second_watcher.try_recv().unwrap(),
        TurnOutcome::Failed { error } if error == "first failure"
    ));
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
    let locks = Arc::new(LockManager::in_memory(db.clone()));
    let session = Arc::new(
        Session::create_for_test(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
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
        None,
        tmp.path().to_path_buf(),
        false,
        false,
        &extended,
        Arc::new(crate::daemon::lsp::LspManager::new()),
        None,
        Arc::new(StdMutex::new(None)),
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

#[tokio::test]
async fn worker_driver_respects_attached_ignore_config_policy() {
    let env_root = tempfile::tempdir().unwrap();
    let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(env_root.path()).await;
    let project = env_root.path().join("trusted-project");
    std::fs::create_dir_all(&project).unwrap();
    write_model_config(&project);
    let user_cockpit = env_root.path().join("home/.config/cockpit");
    std::fs::create_dir_all(user_cockpit.join("providers")).unwrap();
    std::fs::write(
        user_cockpit.join("config.json"),
        r#"{"active_model":{"provider":"lmstudio","model":"session-model"}}"#,
    )
    .unwrap();
    std::fs::write(
        user_cockpit.join("providers/lmstudio.json"),
        r#"{
              "url": "http://localhost:1/v1",
              "models": [
                {"id": "session-model"},
                {"id": "assistant-model"}
              ]
            }"#,
    )
    .unwrap();

    crate::config::trust::clear_runtime_policy_for_tests();
    let trust_root = crate::config::trust::resolve_trust_root(&project).unwrap();
    crate::config::trust::set_runtime_policy(
        trust_root.clone(),
        crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    );
    let attached_policy = crate::config::trust::WorkspaceTrustPolicy {
        root: trust_root,
        mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
    };

    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            project.clone(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    session
        .set_active_model("lmstudio", "session-model")
        .unwrap();
    let providers = lmstudio_test_providers();
    let redact = Arc::new(RedactionTable::empty());
    let model =
        Arc::new(crate::engine::model::Model::from_config(&providers, redact.clone()).unwrap());
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.sandbox.default_mode = crate::config::sandbox_mode::SandboxMode::Off;
    let (handle, join) = spawn(
        session,
        Arc::new(LockManager::in_memory(db)),
        redact,
        model,
        None,
        None,
        None,
        project.clone(),
        false,
        false,
        &extended,
        Arc::new(crate::daemon::lsp::LspManager::new()),
        None,
        Arc::new(StdMutex::new(None)),
        Arc::new(StdMutex::new(None)),
        None,
        attached_policy,
        None,
        EnvSnapshot::new(
            crate::env_snapshot::EnvSnapshotSource::DaemonStart,
            Default::default(),
        ),
        SessionConfigSnapshot::new(0, providers, extended.clone()),
    );
    let mut events = handle.subscribe();
    let selection_id = Uuid::new_v4();
    handle
        .send_work(SessionWork::SetActiveModel {
            selection_id,
            selection_deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
            provider: "lmstudio".to_string(),
            model: "assistant-model".to_string(),
            persist_as_default: true,
            trigger: crate::session::ModelSwitchTrigger::Picker,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        })
        .await
        .unwrap();

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let proto::Event::ModelSelectionResult {
                selection_id: event_selection_id,
                outcome,
                ..
            } = events.recv().await.unwrap().event
                && event_selection_id == selection_id
            {
                break outcome;
            }
        }
    })
    .await
    .expect("worker emits the terminal model-selection result");
    let proto::ModelSelectionOutcome::Applied {
        active_state,
        default_update,
    } = outcome
    else {
        panic!("attached trusted-project save should apply, got {outcome:?}");
    };
    match &default_update {
        proto::DefaultModelUpdateOutcome::Verified {
            selection,
            unchanged: false,
            ..
        } => {
            // The verified default is exactly what this request asked for; the
            // point of the test is that it persisted under the *attached*
            // policy at all, rather than being refused by the global one.
            assert_eq!(selection.provider, "lmstudio");
            assert_eq!(selection.model, "assistant-model");
        }
        other => panic!(
            "the spawned driver must persist under the attached policy, not the global policy; got {other:?}"
        ),
    };
    assert_eq!(active_state.selection.model, "assistant-model");
    assert_eq!(
        active_state
            .default_selection
            .as_ref()
            .map(|model| model.model.as_str()),
        Some("assistant-model")
    );
    assert!(!active_state.diverged);

    let project_active =
        crate::config::providers::ConfigDoc::load(&project.join(".cockpit").join("config.json"))
            .unwrap()
            .providers()
            .active_model
            .expect("ignored project config retains its original default");
    assert_eq!(project_active.provider, "lmstudio");
    assert_eq!(project_active.model, "session-model");
    let user_active = crate::config::providers::ConfigDoc::load(&user_cockpit.join("config.json"))
        .unwrap()
        .providers()
        .active_model
        .expect("user-layer default is persisted");
    assert_eq!(user_active.provider, "lmstudio");
    assert_eq!(user_active.model, "assistant-model");

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
    crate::config::trust::clear_runtime_policy_for_tests();
}

#[tokio::test]
async fn resumed_worker_rederives_disk_redaction_markers_and_warns_when_source_disappears() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    let env_path = tmp.path().join(".env");
    let secret = "worker-resume-dotenv-secret-123456";
    std::fs::write(&env_path, format!("TOKEN={secret}\n")).unwrap();

    let redaction_cfg = crate::config::extended::RedactConfig {
        scan_environment: false,
        scan_dotenv: true,
        scan_ssh_keys: false,
        ..Default::default()
    };
    let env = HashMap::new();
    let initial =
        Arc::new(RedactionTable::build_with_env(&redaction_cfg, tmp.path(), &env).unwrap());
    session.persist_redaction_table(&initial).unwrap();
    let persisted = initial.to_persisted_json().unwrap();
    assert!(!persisted.contains(secret));
    assert_eq!(
        RedactionTable::persisted_disk_derived_origins(&persisted).unwrap(),
        vec![format!("$dotenv:{}:TOKEN", env_path.display())]
    );

    let providers = lmstudio_test_providers();
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
    let start_worker = |resumed: Arc<Session>, redaction: Arc<RedactionTable>| {
        let model = Arc::new(
            crate::engine::model::Model::from_config(&providers, redaction.clone()).unwrap(),
        );
        spawn(
            resumed,
            Arc::new(LockManager::in_memory(db.clone())),
            redaction,
            model,
            None,
            None,
            None,
            tmp.path().to_path_buf(),
            false,
            false,
            &extended,
            Arc::new(crate::daemon::lsp::LspManager::new()),
            None,
            Arc::new(StdMutex::new(None)),
            Arc::new(StdMutex::new(None)),
            None,
            trust_policy.clone(),
            None,
            EnvSnapshot::new(
                crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                Default::default(),
            ),
            SessionConfigSnapshot::new(0, providers.clone(), extended.clone()),
        )
    };

    let resumed = Arc::new(
        Session::resume_for_test(
            db.clone(),
            session.id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap(),
    );
    let rederived =
        Arc::new(RedactionTable::build_with_env(&redaction_cfg, tmp.path(), &env).unwrap());
    let ((handle, join), success_log) = capture_warn_log(|| start_worker(resumed, rederived));
    assert_ne!(handle.redaction_table().scrub(secret), secret);
    assert!(!success_log.contains("could not be re-derived"));
    handle
        .send_work(SessionWork::Shutdown {
            pause_for_resume: false,
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), join)
        .await
        .unwrap()
        .unwrap();

    std::fs::remove_file(&env_path).unwrap();
    let resumed = Arc::new(
        Session::resume_for_test(
            db.clone(),
            session.id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap(),
    );
    let empty_rederive =
        Arc::new(RedactionTable::build_with_env(&redaction_cfg, tmp.path(), &env).unwrap());
    let ((handle, join), warning_log) = capture_warn_log(|| start_worker(resumed, empty_rederive));
    assert!(warning_log.contains("disk-derived redaction entry could not be re-derived"));
    assert!(warning_log.contains(&env_path.display().to_string()));
    assert!(!warning_log.contains(secret));
    handle
        .send_work(SessionWork::Shutdown {
            pause_for_resume: false,
        })
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), join)
        .await
        .unwrap()
        .unwrap();
}

/// An [`ExtendedConfig`] pinning `defaultPrimaryAgent` for fallback tests.
fn cfg_with(
    default_primary: crate::config::extended::DefaultPrimaryAgent,
) -> crate::config::extended::ExtendedConfig {
    crate::config::extended::ExtendedConfig {
        default_primary_agent: default_primary,
        ..Default::default()
    }
}

struct IsolatedCockpitEnv {
    _guard: crate::test_env::TestEnvGuard,
}

impl IsolatedCockpitEnv {
    async fn new_async(root: &std::path::Path) -> Self {
        Self {
            _guard: crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(root).await,
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
            prompt_cache_retention: None,
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
        swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        granted_tools: Vec::new(),
        lock_identity: None,
        write_scope: None,
        credential_store: None,
    }
}

#[tokio::test]
async fn roster_trim_initial_active_agent_uses_build_or_plan() {
    use crate::config::extended::DefaultPrimaryAgent as D;

    assert_eq!(initial_active_agent(&cfg_with(D::Build)), "Build");
    assert_eq!(initial_active_agent(&cfg_with(D::Plan)), "Plan");
}

#[tokio::test]
async fn plan_default_stale_session_keeps_plan() {
    use crate::config::extended::DefaultPrimaryAgent as D;
    let db = crate::db::Db::open_in_memory().unwrap();
    // A session persisted on Plan loads on Plan. Removed primaries fall back to
    // Build through the shared predicate.
    let row = db.create_session("proj", "/proj", "Plan").await.unwrap();
    assert_eq!(
        resolve_root_agent(
            row.session_id,
            &db,
            &cfg_with(D::Build),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "Plan"
    );
    let swarm = db.create_session("proj", "/proj", "Swarm").await.unwrap();
    assert_eq!(
        resolve_root_agent(
            swarm.session_id,
            &db,
            &cfg_with(D::Build),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "Build"
    );
    assert_eq!(
        resolve_root_agent(
            swarm.session_id,
            &db,
            &cfg_with(D::Plan),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "Build",
        "removed stored primaries force Build, not the configured default"
    );
}

#[tokio::test]
async fn resolve_root_agent_preserves_stored_defensive_primary() {
    use crate::config::extended::DefaultPrimaryAgent as D;

    let db = crate::db::Db::open_in_memory().unwrap();
    let row = db.create_session("proj", "/proj", "Careful").await.unwrap();

    assert_eq!(
        resolve_root_agent(
            row.session_id,
            &db,
            &cfg_with(D::Build),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "Careful"
    );
    assert_eq!(
        resolve_root_agent(
            row.session_id,
            &db,
            &cfg_with(D::Plan),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "Careful",
        "stored Careful primary must survive resume instead of falling back to the configured default"
    );
}

#[tokio::test]
async fn resumed_default_named_session_is_not_auto_swapped_in_defensive_mode() {
    use crate::config::extended::{DefaultPrimaryAgent as D, LlmMode};

    let db = crate::db::Db::open_in_memory().unwrap();
    let row = db.create_session("proj", "/proj", "Build").await.unwrap();

    assert_eq!(
        resolve_root_agent(row.session_id, &db, &cfg_with(D::Build), LlmMode::Defensive).await,
        "Build",
        "stored Build is an explicit resume choice and must not auto-select Careful"
    );
}

#[tokio::test]
async fn roster_trim_removed_primary_notice_is_one_time() {
    use crate::config::extended::DefaultPrimaryAgent as D;

    let db = crate::db::Db::open_in_memory().unwrap();
    let row = db.create_session("proj", "/proj", "Swarm").await.unwrap();

    assert_eq!(
        resolve_root_agent(
            row.session_id,
            &db,
            &cfg_with(D::Build),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "Build"
    );
    let notice = removed_primary_notice(row.session_id, &db, &cfg_with(D::Plan))
        .await
        .expect("first notice");
    assert_eq!(
        notice,
        "Primary agent `Swarm` was removed; continuing with `Build`."
    );

    db.insert_session_event(
        row.session_id,
        crate::db::session_log::SessionEventKind::Notice,
        None,
        None,
        &serde_json::json!({
            "text": notice,
            "severity": "info",
            "source": NoticeSource::DaemonDirect.as_str(),
        }),
    )
    .await
    .unwrap();
    assert!(
        removed_primary_notice(row.session_id, &db, &cfg_with(D::Plan))
            .await
            .is_none(),
        "notice is de-duped once recorded"
    );
}

#[tokio::test]
async fn roster_trim_removed_default_primary_notice_is_one_time() {
    let db = crate::db::Db::open_in_memory().unwrap();
    let row = db.create_session("proj", "/proj", "Build").await.unwrap();
    let mut cfg = cfg_with(crate::config::extended::DefaultPrimaryAgent::Build);
    cfg.removed_default_primary_agent = Some("auto".to_string());

    let notice = removed_primary_notice(row.session_id, &db, &cfg)
        .await
        .expect("first notice");
    assert_eq!(
        notice,
        "Default primary agent `auto` was removed; continuing with `Build`."
    );

    db.insert_session_event(
        row.session_id,
        crate::db::session_log::SessionEventKind::Notice,
        None,
        None,
        &serde_json::json!({
            "text": notice,
            "severity": "info",
            "source": NoticeSource::DaemonDirect.as_str(),
        }),
    )
    .await
    .unwrap();
    assert!(
        removed_primary_notice(row.session_id, &db, &cfg)
            .await
            .is_none(),
        "config-default notice is de-duped once recorded"
    );
}

#[tokio::test]
async fn resolve_root_agent_assistant_session_bypasses_primary_allowlist() {
    use crate::config::extended::DefaultPrimaryAgent as D;
    let db = crate::db::Db::open_in_memory().unwrap();
    db.upsert_assistant("helper-bot", "/tmp/helper-bot", "{}", "hash")
        .await
        .unwrap();
    let row = db
        .create_assistant_session("proj", "/proj", "helper-bot", "helper-bot")
        .await
        .unwrap();

    assert_eq!(
        resolve_root_agent(
            row.session_id,
            &db,
            &cfg_with(D::Build),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "helper-bot"
    );
}

#[tokio::test]
async fn resolve_root_agent_deleted_assistant_falls_back_to_default_primary() {
    use crate::config::extended::DefaultPrimaryAgent as D;
    let db = crate::db::Db::open_in_memory().unwrap();
    let row = db
        .create_assistant_session("proj", "/proj", "missing-bot", "missing-bot")
        .await
        .unwrap();

    assert_eq!(
        resolve_root_agent(
            row.session_id,
            &db,
            &cfg_with(D::Build),
            crate::config::extended::LlmMode::Normal
        )
        .await,
        "Build"
    );
}

#[tokio::test]
async fn assistant_session_root_agent_loads_assistant_definition() {
    use crate::agents::AgentMode;
    use crate::assistants::{CreateAssistantSpec, create_assistant};
    use crate::config::extended::DefaultPrimaryAgent as D;

    let tmp = tempfile::tempdir().unwrap();
    let _env = IsolatedCockpitEnv::new_async(tmp.path()).await;
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
    .await
    .unwrap();
    let row = db
        .create_assistant_session("proj", cwd.to_str().unwrap(), "helper-bot", "helper-bot")
        .await
        .unwrap();

    let root_agent_name = resolve_root_agent(
        row.session_id,
        &db,
        &cfg_with(D::Build),
        crate::config::extended::LlmMode::Normal,
    )
    .await;
    let root = crate::engine::builtin::load_with_assistant_db_and_tool_surface_override(
        &root_agent_name,
        &test_spawn_args(&cwd),
        &db,
        None,
    )
    .await
    .unwrap();

    assert_eq!(root.name, "helper-bot");
    assert!(root.role_prompt.contains("ASSISTANT_DEFINITION_MARKER"));
    assert!(root.system.contains("ASSISTANT_DEFINITION_MARKER"));
    assert_eq!(root.model.provider_id(), "lmstudio");
    assert_eq!(root.model.model_id_ref(), "assistant-model");
    assert!(root.tools.names().contains(&"read"));
}

#[tokio::test]
async fn sandbox_default_precedence_daemon_wins() {
    use crate::tools::sandbox_mode::SandboxMode;
    use cockpit_proto::FeatureCapabilityState;

    let caps = crate::daemon::session_worker::sandbox_capability_snapshot(
        FeatureCapabilityState::Available,
        FeatureCapabilityState::Available,
    );

    // (a) daemon `--no-sandbox` -> OFF regardless of the client flag.
    assert_eq!(
        resolve_sandbox_default_with(true, false, SandboxMode::Sandbox, &caps),
        SandboxMode::Off
    );
    assert_eq!(
        resolve_sandbox_default_with(true, true, SandboxMode::Container, &caps),
        SandboxMode::Off
    );
}

#[tokio::test]
async fn sandbox_default_precedence_client_then_on() {
    use crate::tools::sandbox_mode::SandboxMode;
    use cockpit_proto::FeatureCapabilityState;

    let caps = crate::daemon::session_worker::sandbox_capability_snapshot(
        FeatureCapabilityState::Available,
        FeatureCapabilityState::Available,
    );

    // (b) no daemon flag, client `--no-sandbox` -> OFF.
    assert_eq!(
        resolve_sandbox_default_with(false, true, SandboxMode::Container, &caps),
        SandboxMode::Off
    );
    // (c) neither flag -> effective intent (host Sandbox when available).
    assert_eq!(
        resolve_sandbox_default_with(false, false, SandboxMode::Sandbox, &caps),
        SandboxMode::Sandbox
    );
}

#[test]
fn set_sandbox_rejects_unavailable_intent_does_not_persist() {
    use crate::tools::sandbox_mode::SandboxMode;
    use cockpit_proto::FeatureCapabilityState;

    let tmp = tempfile::TempDir::new().unwrap();
    let db = crate::db::Db::open_in_memory().unwrap();
    let session = crate::session::Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    session.set_sandbox_mode(SandboxMode::Off);
    let locks = Arc::new(crate::locks::LockManager::in_memory(db));
    let handle = SessionWorkerHandle::test_handle(Arc::new(session), locks);
    let missing = crate::daemon::session_worker::sandbox_capability_snapshot(
        FeatureCapabilityState::Missing,
        FeatureCapabilityState::Missing,
    );
    let err = handle
        .set_sandbox(Some(SandboxMode::Sandbox), None, &missing)
        .expect_err("host Sandbox must reject when cap is missing");
    assert!(matches!(
        err,
        crate::daemon::session_worker::SetSandboxError::CapabilityMissing(_)
    ));
    assert_eq!(handle.session().sandbox_mode(), SandboxMode::Off);
    assert!(!tmp.path().join(".cockpit").join("config.json").exists());

    let err = handle
        .set_sandbox(Some(SandboxMode::Container), None, &missing)
        .expect_err("container must reject when cap is missing");
    assert!(matches!(
        err,
        crate::daemon::session_worker::SetSandboxError::CapabilityMissing(_)
    ));
    assert_eq!(handle.session().sandbox_mode(), SandboxMode::Off);

    let available = crate::daemon::session_worker::sandbox_capability_snapshot(
        FeatureCapabilityState::Available,
        FeatureCapabilityState::Available,
    );
    let applied = handle
        .set_sandbox(Some(SandboxMode::Sandbox), None, &available)
        .expect("available Sandbox persists");
    assert_eq!(applied.persisted_intent, SandboxMode::Sandbox);
    assert_eq!(applied.effective, SandboxMode::Sandbox);
    assert_eq!(handle.session().sandbox_mode(), SandboxMode::Sandbox);
}

#[test]
fn sandbox_flag_zero_does_not_disable() {
    let env = crate::test_env::lock();
    env.set_var(DAEMON_NO_SANDBOX_ENV, "0");
    assert!(!daemon_no_sandbox().unwrap());
}

#[test]
fn sandbox_flag_one_disables() {
    let env = crate::test_env::lock();
    env.set_var(DAEMON_NO_SANDBOX_ENV, "1");
    assert!(daemon_no_sandbox().unwrap());
}

#[test]
fn sandbox_flag_invalid_value_is_rejected() {
    let env = crate::test_env::lock();
    env.set_var(DAEMON_NO_SANDBOX_ENV, "sometimes");
    let error = daemon_no_sandbox().unwrap_err().to_string();
    assert!(error.contains("COCKPIT_DAEMON_NO_SANDBOX"));
    assert!(error.contains("sometimes"));
}

/// The concurrent-write-during-plan warning fires once per plan episode per
/// session, re-arms on a different plan, and is mode-aware
/// (`plan-concurrent-build-and-merge.md`).
#[tokio::test]
async fn lifecycle_turn_id_maps_to_proto_events() {
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

#[tokio::test]
async fn foreground_input_target_maps_to_proto_event() {
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

#[tokio::test]
async fn nested_turn_event_maps_to_wrapped_proto_event() {
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

#[tokio::test]
async fn live_foreground_snapshot_tracks_nested_active_subagent() {
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

#[tokio::test]
async fn routing_amend_does_not_alter_foreground_state() {
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
        model_trusted: false,
        routing: serde_json::json!({ "resolved_model": "parent-model" }),
    };
    let amend = TurnEvent::SubagentRouting {
        task_call_id: "task-1".into(),
        label: "default".into(),
        child: "explore".into(),
        provider: "lmstudio".into(),
        model: "child-model".into(),
        model_trusted: true,
        routing: serde_json::json!({ "resolved_model": "child-model" }),
    };
    let report = TurnEvent::SubagentReport {
        agent: "explore".into(),
        task_call_id: "task-1".into(),
        label: "default".into(),
        report: "done".into(),
        failed: false,
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
#[tokio::test]
async fn sandbox_unavailable_maps_to_broadcast_with_remedy() {
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

#[tokio::test]
async fn command_capability_unavailable_maps_to_broadcast_with_fix_command() {
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
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
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
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
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
        .await
        .unwrap();
    let _queued = db
        .raise_interrupt_questions(session_id, "Build", "queued", &set)
        .await
        .unwrap();
    let locks = Arc::new(LockManager::in_memory(db));
    let handle = SessionWorkerHandle::test_handle(Arc::new(session), locks);

    let mut rx = handle.subscribe();
    handle.broadcast_active_interrupt().await;

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

#[tokio::test]
async fn shutdown_activity_snapshot_counts_open_and_parked_interrupts_as_pending_paused_work() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
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
        .await
        .unwrap();
    let parked = db
        .raise_interrupt_questions(session_id, "Build", "parked", &set)
        .await
        .unwrap();
    assert!(db.park_interrupt(parked).await.unwrap());

    let live = LiveState::default();
    let interrupts = crate::engine::interrupt::InterruptHub::detached();
    let (active, pending_tool_count, _committed) =
        shutdown_activity_snapshot(&session, session_id, &interrupts, &live).await;

    assert!(active, "blocked-only sessions must be paused on shutdown");
    assert_eq!(
        pending_tool_count, 2,
        "paused row count must include both open and already-parked interrupts"
    );
    assert_eq!(db.list_open_interrupts(session_id).await.unwrap().len(), 2);
    assert!(db.get_interrupt(open).await.unwrap().is_some());
}

/// §6.5 de-dupe: the latch fires the broadcast exactly once per condition.
/// Two failed `bash` calls (two `SandboxUnavailable` events) → one forward;
/// `set_sandbox` re-arms it (clearing the latch) so a renewed condition
/// after a `/sandbox` toggle can surface a fresh notice.
#[tokio::test]
async fn sandbox_unavailable_dedupes_per_session() {
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
#[tokio::test]
async fn detach_should_release_only_on_last_detach_while_idle() {
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
    let sid = db
        .create_session("p", "/x", "builder")
        .await
        .unwrap()
        .session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).await.unwrap();

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
    let sid = db
        .create_session("p", "/x", "builder")
        .await
        .unwrap()
        .session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).await.unwrap();

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
    let sid = db
        .create_session("p", "/x", "builder")
        .await
        .unwrap()
        .session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).await.unwrap();

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
    let sid = db
        .create_session("p", "/x", "builder")
        .await
        .unwrap()
        .session_id;
    let locks = Arc::new(LockManager::in_memory(db));
    locks.acquire(&p, "builder", sid).await.unwrap();

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
            prompt_cache_retention: None,
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
#[tokio::test]
async fn engine_reads_config_through_session_handle() {
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
    let result = replace_config_snapshot(
        &shared,
        SessionConfigSnapshot::new(
            0,
            crate::config::providers::ProvidersConfig::default(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    );
    assert!(result.changed);
    assert_eq!(result.generation, 1);
    assert_eq!(handle.generation(), 1);
}

/// Criterion 3: a turn that started under generation N reads a consistent
/// view for its whole duration; a mid-turn re-resolution does not change
/// what the in-flight turn's (pinned) handle reads, and the next turn's
/// re-pin observes the new generation.
#[tokio::test]
async fn turn_pinned_handle_view_survives_reresolve() {
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
#[tokio::test]
async fn turn_config_values_match_pre_adoption_resolution() {
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
    let (providers, extended) =
        crate::config::trust::with_workspace_trust_policy(trusted_test_policy(tmp.path()), || {
            crate::daemon::config_source::ConfigSource::production().load(tmp.path())
        })
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

#[tokio::test]
async fn config_snapshot_event_still_carries_no_secrets() {
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
fn redacted_extended_config_blanks_image_generation_secrets() {
    use crate::config::image_generation::*;
    use crate::config::providers::{CapabilityStatus, HeaderSpec};
    use chrono::{TimeZone, Utc};

    // Endpoint carrying a raw bearer-token header value + credential reference.
    let endpoint = ImageEndpoint {
        id: "openai-main".into(),
        adapter: ImageAdapterKind::OpenaiImages,
        origin: "https://api.openai.com/".into(),
        path_prefix: None,
        credential_ref: Some("cred-secret-token".into()),
        headers: vec![HeaderSpec {
            name: "Authorization".into(),
            value: "Bearer header-secret-token".into(),
        }],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
        exclusive_server: false,
    }
    .normalized()
    .unwrap();
    let endpoint_identity = endpoint.immutable_identity();

    // Discovered evidence whose `source_url` hides a secret query token. Its
    // `endpoint_identity` must match the endpoint, so a partial in-place
    // redaction that mutated the endpoint would break this binding and panic —
    // exactly why the snapshot omits the registry instead.
    let fetched = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
    let expires = Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap();
    let capability = ImageCapabilityEvidence::new(
        CapabilityStatus::Supported,
        Some(ImageEvidence::Discovered {
            source_url: "https://disc.example.com/models?access_token=evidence-secret-token".into(),
            fetched_at: fetched,
            expires_at: expires,
            endpoint_identity: endpoint_identity.clone(),
        }),
    )
    .unwrap();

    // Standalone workflow whose opaque `graph_json` hides a token anywhere.
    let graph_json =
        r#"{"1":{"inputs":{"seed":1,"api_key":"graph-secret-token"}},"2":{"inputs":{}}}"#
            .to_owned();
    let workflow = RegisteredComfyWorkflow {
        id: "wf-1".into(),
        graph_digest: canonical_workflow_digest(&graph_json).unwrap(),
        graph_json,
        bindings: vec![WorkflowBinding {
            parameter: ImageParameter::Seed,
            node_id: "1".into(),
            input: "seed".into(),
            value_type: WorkflowValueType::Integer,
            min: Some(0),
            max: Some(1_000_000),
        }],
        outputs: vec![WorkflowOutput {
            node_id: "2".into(),
            output: "images".into(),
            value_type: WorkflowValueType::Image,
        }],
    };

    let registry = ImageGenerationConfig::new(
        vec![endpoint],
        vec![ImageGenerationTarget {
            id: "gpt-image".into(),
            display_name: None,
            endpoint_id: "openai-main".into(),
            identity: ImageTargetIdentity::HostedModel {
                model: "gpt-image-1".into(),
            },
            enabled: true,
            is_default: true,
            formats: vec![ImageFormat::Png],
            reference_support: ReferenceImageSupport::Unsupported,
            max_reference_images: 0,
            max_samples: 1,
            max_outputs: 1,
            dimensions: ImageDimensionDescriptor::ProviderDefault,
            dimension_policy: ImageDimensionRequestPolicy::ProviderDefault,
            parameters: vec![],
            openrouter_routing: None,
            generation_capability: capability,
            price: ImagePrice::Unknown,
        }],
        vec![workflow],
        vec![],
    )
    .unwrap();

    // Put the secret-bearing registry into a real session config snapshot.
    let mut snapshot = snapshot_for_tests();
    snapshot.extended.image_generation = registry.clone();

    // Go through the ACTUAL client-facing serialization path (`to_proto`), not
    // the redaction helper directly, so bypassing the helper inside to_proto
    // would fail this test.
    let wire = snapshot.to_proto(Uuid::new_v4());

    // (b) The snapshot omits image-generation content entirely (empty
    // registry): no panic on discovered evidence, no reliance on selectively
    // scrubbing opaque graph_json.
    assert_eq!(
        wire.extended.image_generation,
        ImageGenerationConfig::default()
    );

    // (a) The serialized proto clients receive leaks none of the secrets.
    let encoded = serde_json::to_string(&wire).unwrap();
    for secret in [
        "header-secret-token",
        "cred-secret-token",
        "graph-secret-token",
        "evidence-secret-token",
        "access_token=evidence-secret-token",
    ] {
        assert!(!encoded.contains(secret), "leaked {secret}: {encoded}");
    }

    // (c) Redaction is snapshot-only: the live source config is not mutated.
    assert_eq!(snapshot.extended.image_generation, registry);
}

#[tokio::test]
async fn config_snapshot_carries_resolved_provider_view() {
    let wire = snapshot_for_tests().to_proto(Uuid::new_v4());
    assert_eq!(
        wire.providers.active_model.as_ref().unwrap().model,
        "gpt-test"
    );
    let provider = wire.providers.providers.get("openai").unwrap();
    assert_eq!(provider.entry.url, "https://api.openai.example/v1");
    assert_eq!(provider.entry.models[0].context_length, Some(128_000));
}

#[tokio::test]
async fn provider_view_covers_enumerated_tui_consumer_fields() {
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

#[tokio::test]
async fn provider_view_requires_no_client_side_secret_resolution() {
    let wire = snapshot_for_tests().to_proto(Uuid::new_v4());
    let provider = wire.providers.providers.get("openai").unwrap();
    assert!(provider.entry.credential_ref.is_none());
    assert!(provider.entry.headers.is_empty());
    assert!(provider.credential_configured);
}

#[tokio::test]
async fn replace_config_snapshot_unchanged_values_do_not_bump_generation() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let replacement = snapshot.read().unwrap().clone();
    let result = replace_config_snapshot(&snapshot, replacement);
    assert!(!result.changed);
    assert_eq!(result.generation, 0);
    assert_eq!(snapshot.read().unwrap().generation, 0);
}

#[tokio::test]
async fn replace_config_snapshot_changed_values_bump_generation() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let result = replace_config_snapshot(
        &snapshot,
        SessionConfigSnapshot::new(
            0,
            crate::config::providers::ProvidersConfig::default(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    );
    assert!(result.changed);
    assert_eq!(result.generation, 1);
}

#[tokio::test]
async fn config_snapshot_generation_stable_without_reresolve() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let before = snapshot.read().unwrap().generation;
    let _current = snapshot.read().unwrap().clone();
    assert_eq!(snapshot.read().unwrap().generation, before);
}

#[tokio::test]
async fn invalid_config_reresolve_keeps_last_good_snapshot() {
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

#[tokio::test]
async fn config_reresolve_does_not_mutate_inflight_turn_view() {
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

#[tokio::test]
async fn llm_mode_reads_are_consistent_within_a_generation() {
    let tmp = tempfile::tempdir().unwrap();
    let snapshot = snapshot_for_tests();
    let session = Session::create_for_test(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
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

#[tokio::test]
async fn session_llm_mode_stays_immediate_and_prune_free() {
    use crate::config::extended::LlmMode;
    use crate::engine::driver::DriverControl;

    assert!(matches!(
        persistent_llm_mode_control(LlmMode::Frontier),
        DriverControl::SetLlmMode {
            mode: Some(LlmMode::Frontier),
            prune_after_switch: true
        }
    ));
    assert!(matches!(
        session_llm_mode_control(LlmMode::Frontier),
        DriverControl::SetLlmMode {
            mode: Some(LlmMode::Frontier),
            prune_after_switch: false
        }
    ));
}

#[tokio::test]
async fn stored_session_llm_mode_restores_before_startup_resolution() {
    use crate::config::extended::LlmMode;

    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let created = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    created.set_session_llm_mode(LlmMode::Frontier).unwrap();

    let resumed = Session::resume_for_test(
        db,
        created.id,
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(stored_session_llm_mode(&resumed), Some(LlmMode::Frontier));
}

#[tokio::test]
async fn invalid_stored_session_llm_mode_is_rejected_by_the_database() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let created = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();

    let error = db
        .set_session_llm_mode(created.id, Some("turbo"))
        .await
        .unwrap_err();

    let message = format!("{error:#}");
    assert!(message.contains("CHECK constraint failed"), "{message}");
}

#[tokio::test]
async fn stored_tool_surface_override_decodes_for_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db,
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    session
        .set_tool_surface_override_json(Some(
            r#"{"tools":["read","mcp","session_search"],"toolTiers":{"session_search":"discoverable"}}"#
                .to_string(),
        ))
        .unwrap();

    let selection = stored_tool_surface_override(&session).unwrap();
    assert_eq!(
        selection.tools,
        vec![
            "read".to_string(),
            "mcp".to_string(),
            "session_search".to_string()
        ]
    );
    assert_eq!(
        selection.tool_tiers.get("session_search"),
        Some(&crate::agents::ToolTier::Discoverable)
    );
}

#[tokio::test]
async fn invalid_stored_tool_surface_override_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create_for_test(
        db,
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    session
        .set_tool_surface_override_json(Some("not json".to_string()))
        .unwrap();

    assert_eq!(stored_tool_surface_override(&session), None);
}

#[tokio::test]
async fn resume_reapplies_goal_settings_override() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let created = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    created
        .set_goal_settings_override_json(Some(
            r#"{"enabled":false,"coldSkepticCount":2,"maxVerificationAttempts":1}"#.to_string(),
        ))
        .unwrap();

    let resumed = Session::resume_for_test(
        db,
        created.id,
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap()
    .unwrap();
    let override_ = stored_goal_settings_override(&resumed).unwrap();

    assert_eq!(override_.cold_skeptic_count, Some(2));
    assert_eq!(override_.max_verification_attempts, Some(1));
}

#[tokio::test]
async fn resume_ignores_invalid_goal_settings_override() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let created = Session::create_for_test(
        db.clone(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    created
        .set_goal_settings_override_json(Some(r#"{"coldSkepticCount":0}"#.to_string()))
        .unwrap();

    let resumed = Session::resume_for_test(
        db,
        created.id,
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(stored_goal_settings_override(&resumed), None);
}

#[tokio::test]
async fn worker_uses_registry_resolved_config_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let snapshot = snapshot_for_tests();
    let session = Session::create_for_test(
        Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    session.set_active_model("openai", "gpt-test").unwrap();
    crate::config::extended::reset_load_for_cwd_call_count();
    let _ = resolve_effective_llm_mode(&session, &snapshot.providers, snapshot.extended.llm_mode);
    assert_eq!(crate::config::extended::load_for_cwd_call_count(), 0);
}

#[tokio::test]
async fn worker_broadcast_delivers_config_snapshot_to_subscriber() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    let locks = Arc::new(LockManager::in_memory(db));
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

#[tokio::test]
async fn replace_config_snapshot_no_change_emits_no_config_snapshot_event() {
    let snapshot = Arc::new(RwLock::new(snapshot_for_tests()));
    let (event_tx, mut event_rx) = tokio::sync::broadcast::channel(16);
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
    let session_id = Uuid::new_v4();
    let replacement = snapshot.read().unwrap().clone();

    let result = replace_config_snapshot(&snapshot, replacement);
    let generation =
        send_config_snapshot_event_if_changed(&event_tx, &redaction, &snapshot, session_id, result);

    assert_eq!(generation, 0);
    assert!(event_rx.try_recv().is_err());
}

#[tokio::test]
async fn dispatch_reresolve_fans_out_to_all_attached_clients() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    let locks = Arc::new(LockManager::in_memory(db));
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
#[tokio::test]
async fn session_scoped_code_has_no_direct_config_reads() {
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
        // Owner ExportPolicy/ImportPolicy surface: a session-less owner RPC
        // that renders/applies a portable policy bundle for a `project_root`,
        // with no attached session to read a snapshot from (mirrors
        // `session/export/mod.rs` and `wizard/apply.rs`).
        "policy.rs",
    ];

    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(&src_dir, &mut files);

    // The primitive disk loaders plus the `auto_title::load_configs_for`
    // convenience that pairs them: a turn-scoped call to any of these
    // bypasses the session snapshot.
    let banned = [
        "load_for_cwd(",
        "load_for_cwd_for_daemon",
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

#[tokio::test]
async fn config_reresolve_rereads_trust_policy() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dispatch =
        std::fs::read_to_string(manifest_dir.join("src/daemon/server/dispatch.rs")).unwrap();
    let refresh = dispatch
        .split("Request::RefreshConfig =>")
        .nth(1)
        .and_then(|tail| tail.split("Request::RecordUsage").next())
        .expect("RefreshConfig dispatch arm");
    assert!(
        refresh.contains("refresh_session_config"),
        "dispatch refresh arm should call the shared config refresh helper"
    );

    let shared = std::fs::read_to_string(manifest_dir.join("src/daemon/config_refresh.rs"))
        .expect("shared config refresh helper");
    let trust_pos = shared
        .find("resolve_workspace_trust_policy_from_db")
        .expect("refresh re-reads trust policy");
    let load_pos = shared
        .find("load_effective_for_daemon")
        .expect("refresh loads through ConfigSource with trust");
    let replace_pos = shared
        .find("ReplaceConfigSnapshot")
        .expect("refresh sends replacement through session worker");
    assert!(
        trust_pos < load_pos && load_pos < replace_pos,
        "trust must be re-read before config load and worker replacement"
    );
}

#[tokio::test]
async fn queue_item_carries_display_text() {
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

// ---------------------------------------------------------------------------
// `sessionEnd` hook matcher: closed deterministic WorkerStop -> matcher map.
// ---------------------------------------------------------------------------

#[test]
fn session_end_matcher_maps_worker_stop() {
    // Expectations are INDEPENDENT literals (Decision 3), not re-derived from
    // the mapping code. The config-allowed closed matcher set for
    // `HookEvent::SessionEnd`.
    let allowed = ["completed", "interrupted", "cancelled", "shutdown", "error"];

    // A failed driver is the ONLY `error`.
    assert_eq!(WorkerStop::DriverFailed.session_end_matcher(), "error");
    // A driver that exited on its own is a clean completion.
    assert_eq!(WorkerStop::DriverExited.session_end_matcher(), "completed");
    // An explicit worker stop is a clean completion.
    assert_eq!(WorkerStop::WorkerStopped.session_end_matcher(), "completed");
    // A resumable daemon drain reports `shutdown` (session stays resumable).
    assert_eq!(
        WorkerStop::Shutdown {
            pause_for_resume: true,
            active: true,
            pending_tool_count: 3,
        }
        .session_end_matcher(),
        "shutdown"
    );
    assert_eq!(
        WorkerStop::Shutdown {
            pause_for_resume: true,
            active: false,
            pending_tool_count: 0,
        }
        .session_end_matcher(),
        "shutdown"
    );
    // A non-resumable shutdown is a clean completion, NOT `shutdown`.
    assert_eq!(
        WorkerStop::Shutdown {
            pause_for_resume: false,
            active: false,
            pending_tool_count: 0,
        }
        .session_end_matcher(),
        "completed"
    );

    // Every produced matcher is inside the config-allowed closed set.
    for stop in [
        WorkerStop::DriverFailed,
        WorkerStop::DriverExited,
        WorkerStop::WorkerStopped,
        WorkerStop::Shutdown {
            pause_for_resume: true,
            active: true,
            pending_tool_count: 1,
        },
        WorkerStop::Shutdown {
            pause_for_resume: false,
            active: false,
            pending_tool_count: 0,
        },
    ] {
        assert!(
            allowed.contains(&stop.session_end_matcher()),
            "{stop:?} -> {} is outside the closed sessionEnd matcher set",
            stop.session_end_matcher()
        );
    }

    // The matcher must NOT be the human-readable `session_ended_reason` proto
    // text: `DriverExited` reports proto reason "driver exited" but matcher
    // "completed"; `DriverFailed` reports "driver failed" but matcher "error".
    // This proves the closed map, not a string-match on the proto reason.
    assert_eq!(
        WorkerStop::DriverExited.session_ended_reason(),
        "driver exited"
    );
    assert_ne!(
        WorkerStop::DriverExited.session_end_matcher(),
        WorkerStop::DriverExited.session_ended_reason()
    );
    assert_eq!(
        WorkerStop::DriverFailed.session_ended_reason(),
        "driver failed"
    );
    assert_ne!(
        WorkerStop::DriverFailed.session_end_matcher(),
        WorkerStop::DriverFailed.session_ended_reason()
    );
}
