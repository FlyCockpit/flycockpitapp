#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::session_worker::SessionWorkerHandle;
    use crate::daemon::shutdown::ShutdownPhase;
    use crate::session::Session;
    use std::collections::{HashMap, HashSet};
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
            agent: "Build".to_string(),
            call_id: "call-1".to_string(),
            tool: "bash".to_string(),
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

    fn test_ctx() -> Arc<DaemonContext> {
        let db = Db::open_in_memory().expect("in-memory db");
        let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
        let paths = DaemonPaths {
            socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
            pid_file: std::path::PathBuf::from("/tmp/cockpit-test.pid"),
            ephemeral: true,
        };
        Arc::new(DaemonContext::new(db, locks, paths))
    }

    fn persistent_test_ctx() -> Arc<DaemonContext> {
        let db = Db::open_in_memory().expect("in-memory db");
        let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
        let paths = DaemonPaths {
            socket: std::path::PathBuf::from("/tmp/cockpit-persistent-test.sock"),
            pid_file: std::path::PathBuf::from("/tmp/cockpit-persistent-test.pid"),
            ephemeral: false,
        };
        Arc::new(DaemonContext::new(db, locks, paths))
    }

    fn remote_state_with_grants(
        grants: Vec<crate::daemon::principal::PrincipalGrant>,
    ) -> ClientState {
        ClientState {
            principal: ClientPrincipal::Remote(crate::daemon::principal::RemotePrincipal {
                user_id: "user-1".into(),
                grants,
            }),
            attached: None,
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

    fn owner_state() -> ClientState {
        ClientState {
            principal: ClientPrincipal::owner(),
            attached: None,
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
        let state_home = tmp.path().join("state");
        let runtime_dir = tmp.path().join("runtime");
        let _env = crate::daemon::test_harness::DaemonEnvGuard::set_paths(&[
            ("XDG_STATE_HOME", state_home.as_path()),
            ("XDG_RUNTIME_DIR", runtime_dir.as_path()),
        ]);
        let ctx = persistent_test_ctx();
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

        let stored = crate::auth::flycockpit::load_credential().unwrap();
        assert_eq!(stored, credential);

        #[cfg(unix)]
        {
            let store = crate::credentials::CredentialStore::open_default().unwrap();
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
        let state_home = tmp.path().join("state");
        let runtime_dir = tmp.path().join("runtime");
        let _env = crate::daemon::test_harness::DaemonEnvGuard::set_paths(&[
            ("XDG_STATE_HOME", state_home.as_path()),
            ("XDG_RUNTIME_DIR", runtime_dir.as_path()),
        ]);
        let ctx = persistent_test_ctx();
        crate::auth::flycockpit::store_credential(&flycockpit_credential()).unwrap();
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
        assert!(crate::auth::flycockpit::load_credential().is_err());
    }

    #[tokio::test]
    async fn ephemeral_daemon_rejects_flycockpit_credential_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let state_home = tmp.path().join("state");
        let runtime_dir = tmp.path().join("runtime");
        let _env = crate::daemon::test_harness::DaemonEnvGuard::set_paths(&[
            ("XDG_STATE_HOME", state_home.as_path()),
            ("XDG_RUNTIME_DIR", runtime_dir.as_path()),
        ]);
        let ctx = test_ctx();
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
        assert!(crate::auth::flycockpit::load_credential().is_err());
    }

    #[tokio::test]
    async fn fs_requests_require_project_files_scope_for_matching_root() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let root_a = tmp.path().join("a");
        let root_b = tmp.path().join("b");
        std::fs::create_dir_all(&root_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();
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

    #[test]
    fn resource_scheduler_is_shared_only_for_persistent_daemons() {
        let persistent_db = Db::open_in_memory().expect("in-memory db");
        let persistent_locks =
            Arc::new(LockManager::from_db(persistent_db.clone()).expect("locks"));
        let persistent = DaemonContext::new(
            persistent_db,
            persistent_locks,
            DaemonPaths {
                socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
                pid_file: std::path::PathBuf::from("/tmp/cockpit-test.pid"),
                ephemeral: false,
            },
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

        let mut state = ClientState::detached_for_test();
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
        let mut state = ClientState::detached_for_test();

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
    ) -> (ClientState, Uuid) {
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
        let handle = SessionWorkerHandle::test_handle(session, locks);
        let event_rx = handle.subscribe();
        (
            ClientState {
                principal: ClientPrincipal::owner(),
                attached: Some(AttachedSession {
                    handle,
                    event_rx,
                    _interactive_guard: None,
                }),
                pending_uploads: HashMap::new(),
                ready_attachments: HashMap::new(),
                upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
                upload_limits: AttachmentUploadLimits::default(),
                terminal_views: HashSet::new(),
                terminal_host: test_terminal_host(),
            },
            session_row.session_id,
        )
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
                mutating: true,
            },
            CommandMetadataCase {
                request: Request::SendUserMessage {
                    text: "hello".into(),
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
                mutating: true,
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
                request: Request::ListAgents,
                kind: "list_agents",
                session_id: None,
                audit_path: None,
                mutating: true,
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
                mutating: true,
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
                request: Request::StopDaemon,
                kind: "stop_daemon",
                session_id: None,
                audit_path: None,
                mutating: true,
            },
        ];

        assert_eq!(
            cases.len(),
            70,
            "every Request variant has one metadata case"
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

    fn overlay_value(state: &ClientState, key: &str) -> Option<String> {
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

    fn begin_upload_for(state: &mut ClientState, png: &[u8]) -> Uuid {
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
        state: &mut ClientState,
        upload_id: Uuid,
    ) -> std::result::Result<Response, ErrorPayload> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(finish_attachment_upload(state, upload_id))
    }

    fn finish_upload_for(state: &mut ClientState, png: &[u8]) -> proto::ImageAttachmentRef {
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

        let err = consume_image_refs(&mut state, session_b, &[image_ref.clone()])
            .expect_err("wrong session must fail");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("different session"));

        let images =
            consume_image_refs(&mut state, session_a, &[image_ref]).expect("owner consume");
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
        let err =
            finish_attachment_upload_for_test(&mut state, upload_id).expect_err("hash mismatch");
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
        let err =
            finish_attachment_upload_for_test(&mut state, upload_id).expect_err("invalid png");
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
            .created_at =
            Instant::now() - Duration::from_secs(proto::PENDING_ATTACHMENT_TTL_SECS + 1);

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

        let attached = state.attached.as_mut().expect("attached session");
        match attached
            .event_rx
            .try_recv()
            .expect("approval broadcast")
            .event
        {
            proto::Event::ApprovalModeState { mode, .. } => {
                assert_eq!(mode, crate::config::extended::ApprovalMode::Yolo);
            }
            other => panic!("expected ApprovalModeState, got {other:?}"),
        }
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
    fn set_agent_allows_build_when_experimental_mode_off() {
        let ownable = vec!["Build".to_string()];

        validate_set_agent_name("Build", false, &ownable)
            .expect("Build remains a chat-ownable primary without experimental mode");
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

    #[tokio::test]
    async fn delete_live_session_timeout_leaves_row_intact() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
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
        let mut state = ClientState::detached_for_test();
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
        let mut state = ClientState::detached_for_test();
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
    async fn cascaded_delete_timeout_stops_before_any_db_mutation() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
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

    /// `/note` (`RecordSessionNote`) records a durable `user_note` session
    /// event and returns its `seq` — without enqueueing any work on a worker
    /// (no inference). The event is queryable for export immediately.
    #[tokio::test]
    async fn record_session_note_persists_event_without_inference() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
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
        let mut state = ClientState::detached_for_test();
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
        let mut state = ClientState::detached_for_test();

        ctx.shutdown.begin_drain();

        let err = handle_request(
            Request::SendUserMessage {
                text: "hi".into(),
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

        let (left, right) = tokio::io::duplex(proto::MAX_FRAME_BYTES);
        let mut server = ProtoStream::new(left);
        let mut client = ProtoStream::new(right);
        let mut state = ClientState::detached_for_test();
        let request_id = Uuid::new_v4();
        handle_envelope(
            Envelope::request(
                request_id,
                Request::Attach {
                    session_id: Some(session.session_id),
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
            &ctx,
            &mut server,
        )
        .await
        .expect("attach envelope handled");

        match recv_body(&mut client).await {
            Body::Response { id, response } => {
                let Response::Attached { session_id, .. } = *response else {
                    panic!("expected Attached response, got {response:?}");
                };
                assert_eq!(id, request_id);
                assert_eq!(session_id, session.session_id);
            }
            other => panic!("expected Attached response, got {other:?}"),
        }
        match recv_body(&mut client).await {
            Body::Event {
                event: proto::Event::DaemonDraining { forced },
            } => assert!(!forced),
            other => panic!("expected DaemonDraining replay, got {other:?}"),
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

        let mut state = ClientState::detached_for_test();
        let response = handle_request(
            Request::Attach {
                session_id: None,
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

        let mut state = ClientState::detached_for_test();
        let response = handle_request(
            Request::Attach {
                session_id: None,
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
        assert!(matches!(client.recv().await.unwrap(), None));
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn attach_requires_db_workspace_trust_row() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let tmp = tempfile::tempdir().unwrap();

        let err = handle_request(
            Request::Attach {
                session_id: None,
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

        assert_eq!(err.code, ErrorCode::Internal);
        assert!(err.message.contains("workspace trust is not set"));
        assert!(state.attached.is_none());
    }

    #[test]
    fn daemon_load_configs_uses_session_policy_over_global_policy() {
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

        let (_, extended) = load_configs_with_trust(ignored.path(), &session_policy).unwrap();

        assert_ne!(extended.max_primary_rounds, 77);
        crate::config::trust::clear_runtime_policy_for_tests();
    }
}
