#[cfg(test)]
mod tests {
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
        tokio::time::advance(STREAM_DELTA_COALESCE_WINDOW - std::time::Duration::from_millis(1))
            .await;
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
        let mut cfg = crate::config::extended::RedactConfig::default();
        cfg.denylist = vec!["secret-user-steer-token".to_string()];
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
        let redaction: SharedRedactionTable =
            Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
        let (driver_tx, mut driver_rx) = mpsc::channel(1);
        let mut notified = HashSet::new();

        refresh_redaction_for_turn(
            &session,
            session.id,
            tmp.path(),
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
        let mut cfg = crate::config::extended::RedactConfig::default();
        cfg.denylist = vec!["session-secret-token".to_string()];
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
        let redaction: SharedRedactionTable =
            Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
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
            proto::Event::SessionDriverFailed { session_id: id, error }
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

        assert!(
            matches!(outcome, DriverOutcome::Panicked(error) if error == "driver panic for test")
        );
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
        _lock: std::sync::MutexGuard<'static, ()>,
        vars: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl IsolatedCockpitEnv {
        fn new(root: &std::path::Path) -> Self {
            let lock = crate::test_env::lock();
            let vars = vec![
                ("XDG_DATA_HOME", std::env::var_os("XDG_DATA_HOME")),
                ("XDG_CONFIG_HOME", std::env::var_os("XDG_CONFIG_HOME")),
                ("XDG_STATE_HOME", std::env::var_os("XDG_STATE_HOME")),
                ("COCKPIT_CONFIG", std::env::var_os("COCKPIT_CONFIG")),
            ];
            unsafe {
                std::env::set_var("XDG_DATA_HOME", root.join("data"));
                std::env::set_var("XDG_CONFIG_HOME", root.join("config"));
                std::env::set_var("XDG_STATE_HOME", root.join("state"));
                std::env::remove_var("COCKPIT_CONFIG");
            }
            Self { _lock: lock, vars }
        }
    }

    impl Drop for IsolatedCockpitEnv {
        fn drop(&mut self) {
            for (name, value) in self.vars.iter().rev() {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
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

    fn test_spawn_args(cwd: &std::path::Path) -> crate::engine::builtin::SpawnArgs {
        use crate::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry, ProvidersConfig};
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let mut providers = BTreeMap::new();
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
        let providers = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".to_string(),
                model: "session-model".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..ProvidersConfig::default()
        };
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
        db.upsert_assistant(
            "helper-bot",
            "/tmp/helper-bot",
            "{}",
            "hash",
        )
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
                model: Some("lmstudio/assistant-model".to_string()),
                prompt: "ASSISTANT_DEFINITION_MARKER".to_string(),
                home_dir: tmp.path().join("assistants/helper-bot"),
            },
        )
        .unwrap();
        let row = db
            .create_assistant_session(
                "proj",
                cwd.to_str().unwrap(),
                "helper-bot",
                "helper-bot",
            )
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
                target: crate::engine::message::QueueTarget::child(
                    "explore", 1, "call-1", "default",
                ),
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
                target: crate::engine::message::QueueTarget::child(
                    "builder", 1, "task-1", "default",
                ),
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
        let fix_command =
            "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0".to_string();
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
