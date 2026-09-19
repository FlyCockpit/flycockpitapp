use super::App;
use crate::tui::agent_runner::GuidanceEstimate;
use cockpit_client::LifecycleIntent;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct TraceBuffer(Arc<Mutex<Vec<u8>>>);

struct TraceWriter(TraceBuffer);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceBuffer {
    type Writer = TraceWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceWriter(self.clone())
    }
}

impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.0.lock().unwrap().write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn reset_startup_counters() {
    cockpit_config::extended::reset_load_for_cwd_call_count();
    cockpit_config::providers::reset_load_effective_call_count();
    cockpit_core::container::reset_detect_runtime_call_count();
    cockpit_core::daemon::reset_blocking_probe_call_count();
    cockpit_tokenizer::reset_count_call_count();
}

fn startup_snapshot(revision: u64) -> cockpit_proto::OnboardingBootstrapSnapshot {
    cockpit_proto::OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(11),
        attempt_id: uuid::Uuid::from_u128(12),
        revision,
        stage: cockpit_proto::OnboardingStage::Complete,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::Ready,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
        last_receipt: None,
    }
}

#[test]
fn app_new_is_a_safe_shell_and_defers_all_startup_work() {
    let tmp = tempfile::tempdir().unwrap();
    reset_startup_counters();

    let app = App::new(Some(tmp.path()), false);

    assert_eq!(cockpit_config::extended::load_for_cwd_call_count(), 0);
    assert_eq!(cockpit_config::providers::load_effective_call_count(), 0);
    assert_eq!(cockpit_core::daemon::blocking_probe_call_count(), 0);
    assert_eq!(cockpit_core::container::detect_runtime_call_count(), 0);
    assert_eq!(cockpit_tokenizer::count_call_count(), 0);
    assert!(app.guidance_estimate.is_none());
    assert!(!app.startup_background.started);
    assert!(!app.first_paint_completed);
}

#[test]
fn first_event_loop_wake_is_fenced_before_every_service_and_first_draw() {
    let source = include_str!("mod.rs");
    let wake = source
        .split("async fn service_event_loop_wake(")
        .nth(1)
        .expect("event-loop wake implementation");
    let fence = wake
        .find("if !self.first_paint_completed")
        .expect("prepaint wake fence");
    for service in [
        "self.ensure_session_for_display()",
        "self.sync_repo_status()",
        "self.drain_async_actions()",
        "self.service_onboarding_shell()",
        "self.maybe_service_new_session(terminal)",
    ] {
        assert!(
            fence < wake.find(service).expect("inventoried wake service"),
            "`{service}` moved ahead of the completed-draw fence"
        );
    }
}

#[test]
fn startup_trace_milestones_are_one_shot_across_retries() {
    let mut app = App::new(None, false);
    for event in [
        "lifetime-policy-error",
        "lifecycle-error",
        "onboarding-error",
        "trust-error",
        "session-error",
    ] {
        assert!(app.mark_startup_trace_milestone(event));
        assert!(!app.mark_startup_trace_milestone(event));
    }
}

#[test]
fn every_interactive_entry_constructs_the_same_zero_io_shell() {
    let tmp = tempfile::tempdir().unwrap();
    reset_startup_counters();
    let (lifecycle, _requests) = cockpit_client::LifecycleClient::channel(8);

    let mut entries = vec![
        App::new_composed_with_session_mode(
            None,
            false,
            cockpit_proto::SessionEntryMode::Code,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session_mode(
            Some(tmp.path()),
            false,
            cockpit_proto::SessionEntryMode::Computer,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session_mode(
            None,
            false,
            cockpit_proto::SessionEntryMode::Assistant,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session_mode(
            None,
            false,
            cockpit_proto::SessionEntryMode::Code,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_named_assistant(
            None,
            false,
            "named".to_string(),
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session(
            None,
            false,
            super::StartupWorkspaceTrust::Decided,
            uuid::Uuid::now_v7(),
            None,
            lifecycle,
        ),
    ];
    entries[3].configure_onboarding_launch(false, true);

    for app in &entries {
        assert!(!app.first_paint_completed);
        assert!(!app.startup_background.started);
        assert_eq!(app.async_actions.pending_count(), 0);
        assert!(app.startup_lifecycle.is_none());
    }
    assert_eq!(cockpit_config::extended::load_for_cwd_call_count(), 0);
    assert_eq!(cockpit_config::providers::load_effective_call_count(), 0);
    assert_eq!(cockpit_core::daemon::blocking_probe_call_count(), 0);
    assert_eq!(cockpit_core::container::detect_runtime_call_count(), 0);
    assert_eq!(cockpit_tokenizer::count_call_count(), 0);
}

#[test]
fn lifecycle_intent_preserves_selected_lifetime_and_assistant_override() {
    let mut code = App::new(None, false);
    code.ephemeral_preference = true;
    assert_eq!(code.lifecycle_intent(), LifecycleIntent::AttachOrEphemeral);
    code.configure_onboarding_launch(true, false);
    assert_eq!(code.lifecycle_intent(), LifecycleIntent::AttachOrEphemeral);

    code.ephemeral_preference = false;
    assert_eq!(code.lifecycle_intent(), LifecycleIntent::AttachOrPersistent);

    let mut assistant = App::new(None, false);
    assistant.session_mode = Some(cockpit_proto::SessionEntryMode::Assistant);
    assistant.ephemeral_preference = true;
    assert_eq!(
        assistant.lifecycle_intent(),
        LifecycleIntent::PromoteToPersistent
    );
}

async fn recorded_startup_intent(
    mode: cockpit_proto::SessionEntryMode,
    background_agents: bool,
    skip: bool,
    force: bool,
) -> LifecycleIntent {
    let (lifecycle, mut requests) = cockpit_client::LifecycleClient::channel(2);
    let mut app = App::new_composed_with_session_mode(
        None,
        false,
        mode,
        super::StartupWorkspaceTrust::Decided,
        None,
        lifecycle,
    );
    app.configure_onboarding_launch(skip, force);
    app.first_paint_completed = true;
    let notify = app.async_actions.notifier();
    let completion = notify.notified();
    app.start_startup_background_tasks_with_policy(async move { Ok(background_agents) });
    completion.await;
    assert!(app.drain_async_actions());
    let request = requests.recv().await.expect("startup lifecycle request");
    let intent = request.intent;
    drop(request);
    drop(app);
    intent
}

#[tokio::test]
async fn selected_lifetime_is_requested_once_after_policy_completion() {
    assert_eq!(
        recorded_startup_intent(cockpit_proto::SessionEntryMode::Code, false, false, false).await,
        LifecycleIntent::AttachOrEphemeral
    );
    assert_eq!(
        recorded_startup_intent(
            cockpit_proto::SessionEntryMode::Computer,
            true,
            false,
            false
        )
        .await,
        LifecycleIntent::AttachOrPersistent
    );
    assert_eq!(
        recorded_startup_intent(cockpit_proto::SessionEntryMode::Code, false, true, false).await,
        LifecycleIntent::AttachOrEphemeral
    );
    assert_eq!(
        recorded_startup_intent(cockpit_proto::SessionEntryMode::Code, false, false, true).await,
        LifecycleIntent::AttachOrEphemeral
    );
    assert_eq!(
        recorded_startup_intent(
            cockpit_proto::SessionEntryMode::Assistant,
            false,
            false,
            false
        )
        .await,
        LifecycleIntent::PromoteToPersistent
    );
}

#[tokio::test]
async fn exit_before_lifetime_policy_completion_closes_unstarted_lifecycle_work() {
    let (lifecycle, mut requests) = cockpit_client::LifecycleClient::channel(1);
    let mut app = App::new_composed_with_session_mode(
        None,
        false,
        cockpit_proto::SessionEntryMode::Code,
        super::StartupWorkspaceTrust::Decided,
        None,
        lifecycle,
    );
    app.first_paint_completed = true;
    app.start_startup_background_tasks_with_policy(std::future::pending());
    app.exit_requested = true;
    drop(app);
    assert!(requests.recv().await.is_none());
}

pub(super) async fn run_startup_trace_case(
    workspace: &std::path::Path,
    runtime: &std::path::Path,
    background_agents: bool,
    resolution_ephemeral: bool,
) -> String {
    let trace = TraceBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(trace.clone())
        .finish();
    let _dispatch = tracing::subscriber::set_default(subscriber);
    cockpit_core::startup::reset_interactive_first_paint();

    let (lifecycle, mut requests) = cockpit_client::LifecycleClient::channel(2);
    let (connections, mut connection_requests) = tokio::sync::mpsc::channel(4);
    let (sensitive, mut sensitive_requests) = tokio::sync::mpsc::channel(1);
    let endpoint = cockpit_client::ClientEndpoint::InProcess(
        cockpit_client::InProcessEndpoint::new(connections, sensitive),
    );
    let fake_daemon = tokio::spawn(async move {
        let sensitive_guard =
            tokio::spawn(async move { while sensitive_requests.recv().await.is_some() {} });
        while let Some(connect) = connection_requests.recv().await {
            let (request_tx, mut request_rx) = tokio::sync::mpsc::channel(8);
            let (_event_tx, event_rx) = tokio::sync::mpsc::channel(1);
            let _ = connect.send(Some(cockpit_client::InProcessConnection {
                requests: request_tx,
                events: event_rx,
            }));
            tokio::spawn(async move {
                while let Some(request) = request_rx.recv().await {
                    let response = match request.request {
                        cockpit_proto::Request::GetOnboardingBootstrapSnapshot => {
                            tracing::info!(
                                target: cockpit_core::startup::TARGET,
                                event = "coverage-phase-start",
                                scope_class = "daemon_global",
                                correlation = "opaque-test-correlation",
                                "startup"
                            );
                            tracing::info!(
                                target: cockpit_core::startup::TARGET,
                                event = "coverage-phase-complete",
                                scope_class = "daemon_global",
                                correlation = "opaque-test-correlation",
                                "startup"
                            );
                            tracing::info!(
                                target: cockpit_core::startup::TARGET,
                                event = "daemon-ready",
                                "startup"
                            );
                            Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(Some(
                                cockpit_proto::OnboardingBootstrapSnapshot {
                                    run_id: uuid::Uuid::from_u128(1),
                                    attempt_id: uuid::Uuid::from_u128(2),
                                    revision: 1,
                                    stage: cockpit_proto::OnboardingStage::Complete,
                                    bootstrap_state: cockpit_proto::OnboardingBootstrapState::Ready,
                                    limited_mode: false,
                                    lifetime_selection: None,
                                    host_capabilities:
                                        cockpit_proto::HostCapabilitySnapshot::unpublished(),
                                    last_receipt: None,
                                },
                            )))
                        }
                        cockpit_proto::Request::GetWorkspaceTrust { .. } => {
                            tracing::info!(
                                target: cockpit_core::startup::TARGET,
                                event = "first-model-request",
                                "startup"
                            );
                            Ok(cockpit_proto::Response::WorkspaceTrust {
                                mode: Some(cockpit_proto::WorkspaceTrustMode::IgnoreConfig),
                                config_generation: 1,
                            })
                        }
                        _ => Err(cockpit_proto::ErrorPayload {
                            code: cockpit_proto::ErrorCode::BadRequest,
                            message: "startup trace fake rejects unlisted request".to_string(),
                        }),
                    };
                    let _ = request.reply.send(response);
                }
            });
        }
        sensitive_guard.abort();
    });
    let mut app = App::new_composed_with_session_mode(
        Some(workspace),
        false,
        cockpit_proto::SessionEntryMode::Code,
        super::StartupWorkspaceTrust::Decided,
        Some(std::time::Instant::now()),
        lifecycle,
    );
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();

    let policy_notify = app.async_actions.notifier();
    let policy_completion = policy_notify.notified();
    app.after_completed_draw_with_policy(async move { Ok(background_agents) });
    policy_completion.await;
    assert!(app.drain_async_actions());

    let request = requests.recv().await.expect("one lifecycle request");
    assert_eq!(
        request.intent,
        if background_agents {
            LifecycleIntent::AttachOrPersistent
        } else {
            LifecycleIntent::AttachOrEphemeral
        }
    );
    let lifecycle_notify = app.async_actions.notifier();
    let lifecycle_completion = lifecycle_notify.notified();
    request
        .reply
        .send(Ok(cockpit_client::LifecycleResolution {
            endpoint,
            lifetime_client: None,
            owns_daemon: background_agents,
            ephemeral_owner: resolution_ephemeral,
            socket: runtime.join("fake-owner.sock"),
            startup_notice: None,
            promoted_from_ephemeral: false,
        }))
        .unwrap();
    lifecycle_completion.await;
    assert!(app.drain_async_actions());

    let onboarding_notify = app.async_actions.notifier();
    let onboarding_completion = onboarding_notify.notified();
    onboarding_completion.await;
    assert!(app.drain_async_actions());

    let workspace_notify = app.async_actions.notifier();
    let workspace_completion = workspace_notify.notified();
    workspace_completion.await;
    assert!(app.drain_async_actions());
    assert!(
        requests.try_recv().is_err(),
        "startup requested a second owner"
    );
    drop(app);
    fake_daemon.abort();

    let output = String::from_utf8(trace.0.lock().unwrap().clone()).unwrap();
    assert!(
        !output.contains(&workspace.display().to_string())
            && !output.contains(&runtime.display().to_string()),
        "startup trace leaked an isolated path: {output}"
    );
    output
}

#[tokio::test(flavor = "current_thread")]
async fn startup_trace_harness_orders_default_and_configured_false_without_real_services() {
    const CHILD: &str = "COCKPIT_STARTUP_TRACE_HARNESS_CHILD";
    const WORKSPACE: &str = "COCKPIT_STARTUP_TRACE_HARNESS_WORKSPACE";
    if std::env::var_os(CHILD).is_none() {
        let namespace = tempfile::tempdir().unwrap();
        for name in ["config", "data", "state", "runtime", "workspace"] {
            std::fs::create_dir(namespace.path().join(name)).unwrap();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env(CHILD, "1")
            .env(WORKSPACE, namespace.path().join("workspace"))
            .env("XDG_CONFIG_HOME", namespace.path().join("config"))
            .env("XDG_DATA_HOME", namespace.path().join("data"))
            .env("XDG_STATE_HOME", namespace.path().join("state"))
            .env("XDG_RUNTIME_DIR", namespace.path().join("runtime"))
            .args([
                "--exact",
                "tui::app::startup_first_paint_tests::startup_trace_harness_orders_default_and_configured_false_without_real_services",
                "--nocapture",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "isolated harness failed: {stderr}");
        assert!(!stderr.contains(&namespace.path().display().to_string()));
        for case in ["default_true", "configured_false"] {
            assert!(
                stderr.contains(&format!("startup-trace-{case}:")),
                "missing captured {case} stderr trace: {stderr}"
            );
        }
        return;
    }

    assert!(std::env::var_os("HOME").is_none());
    let workspace = std::path::PathBuf::from(std::env::var_os(WORKSPACE).unwrap());
    let runtime = std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").unwrap());
    for (case, trace) in [
        (
            "default_true",
            run_startup_trace_case(&workspace, &runtime, true, false).await,
        ),
        (
            "configured_false",
            run_startup_trace_case(&workspace, &runtime, false, true).await,
        ),
    ] {
        let mut cursor = 0;
        for event in [
            "shell-constructed",
            "first-paint",
            "input-ready",
            "lifetime-policy-ready",
            "lifecycle-ready",
            "onboarding-ready",
            "trust-ready",
        ] {
            let relative = trace[cursor..]
                .find(event)
                .unwrap_or_else(|| panic!("missing `{event}` in startup trace: {trace}"));
            cursor += relative + event.len();
        }
        if case == "default_true" {
            assert!(trace.contains("selected_lifetime=\"persistent\""));
            assert!(trace.contains("actual_lifetime=\"persistent\""));
            assert!(trace.contains("outcome=\"spawned\""));
        } else {
            assert!(trace.contains("selected_lifetime=\"ephemeral\""));
            assert!(trace.contains("actual_lifetime=\"ephemeral\""));
            assert!(trace.contains("outcome=\"reused\""));
        }
        assert!(!trace.contains("fake-owner.sock"));
        eprintln!("startup-trace-{case}:{trace}");
    }
}

#[test]
fn startup_guidance_backfill_discards_stale_session_or_model() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.launch.active_model = Some(("provider".to_string(), "model-a".to_string()));
    let estimate = GuidanceEstimate {
        file: Some("AGENTS.md".to_string()),
        guidance_tokens: 10,
        system_tokens: 20,
        model_instruction_tokens: 0,
    };

    app.apply_startup_guidance_estimate(
        app.launch.cwd.clone(),
        Some(("provider".to_string(), "model-b".to_string())),
        estimate.clone(),
    );
    assert!(app.guidance_estimate.is_none());

    app.apply_startup_guidance_estimate(
        app.launch.cwd.join("other"),
        app.launch.active_model.clone(),
        estimate.clone(),
    );
    assert!(app.guidance_estimate.is_none());

    app.apply_startup_guidance_estimate(
        app.launch.cwd.clone(),
        app.launch.active_model.clone(),
        estimate,
    );
    assert_eq!(
        app.guidance_estimate.as_ref().map(|e| e.system_tokens),
        Some(20)
    );
}

#[tokio::test]
async fn startup_background_tasks_are_explicitly_started_after_construction() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    assert!(!app.startup_background.started);
    assert_eq!(app.async_actions.pending_count(), 0);

    app.first_paint_completed = true;
    app.start_startup_background_tasks_with_policy(std::future::pending());

    assert!(app.startup_background.started);
    assert_eq!(app.async_actions.pending_count(), 1);
}

#[test]
fn clipboard_reconciliation_is_off_before_paint_and_for_off_snapshots() {
    let mut app = App::new(None, false);
    app.clipboard_recovery = cockpit_config::extended::ClipboardRecovery::PrivateFile;
    app.schedule_startup_clipboard_reconciliation_with(|| {
        panic!("clipboard work must not start before paint")
    });
    assert_eq!(app.async_actions.pending_count(), 0);

    app.first_paint_completed = true;
    app.clipboard_recovery = cockpit_config::extended::ClipboardRecovery::Off;
    app.schedule_startup_clipboard_reconciliation_with(|| {
        panic!("clipboard work must not start while recovery is off")
    });
    assert_eq!(app.async_actions.pending_count(), 0);
}

#[tokio::test]
async fn private_clipboard_reconciliation_runs_behind_generation_fence() {
    let mut app = App::new(None, false);
    app.first_paint_completed = true;
    app.clipboard_recovery = cockpit_config::extended::ClipboardRecovery::PrivateFile;
    let notify = app.async_actions.notifier();
    let completion = notify.notified();
    app.schedule_startup_clipboard_reconciliation_with(|| {
        Ok(crate::clipboard::recovery::ReconcileReport {
            kept: false,
            removed: 2,
            unsafe_entries_reported: 1,
        })
    });
    completion.await;
    assert!(app.drain_async_actions());
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.text.as_str()),
        Some("Clipboard recovery reconciled: removed 2, unsafe 1")
    );
}

#[tokio::test]
async fn stale_clipboard_reconciliation_completion_is_ui_inert() {
    let mut app = App::new(None, false);
    app.first_paint_completed = true;
    app.clipboard_recovery = cockpit_config::extended::ClipboardRecovery::PrivateFile;
    let notify = app.async_actions.notifier();
    let completion = notify.notified();
    app.schedule_startup_clipboard_reconciliation_with(|| {
        Ok(crate::clipboard::recovery::ReconcileReport {
            kept: false,
            removed: 1,
            unsafe_entries_reported: 0,
        })
    });
    completion.await;
    app.startup_background.generation += 1;
    assert!(app.drain_async_actions());
    assert!(app.toast.is_none());
}

#[test]
fn blocked_export_recovery_cannot_block_first_draw_or_input_ready() {
    let mut app = App::new(None, false);
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    app.after_completed_draw_with_policy(std::future::pending());
    app.schedule_startup_export_recovery(std::future::pending());

    assert!(app.first_paint_completed);
    assert_eq!(app.async_actions.pending_count(), 2);
    assert!(app.startup_lifecycle.is_none());
    assert!(app.agent_runner.is_none());
}

#[test]
fn export_recovery_completion_after_exit_is_ui_inert() {
    use crate::tui::async_action::{
        AsyncActionId, AsyncActionKind, AsyncActionPayload, AsyncActionResult,
    };

    let mut app = App::new(None, false);
    app.exit_requested = true;
    app.apply_async_action_result(AsyncActionResult {
        id: AsyncActionId::from_raw_for_test(87),
        kind: AsyncActionKind::Internal("startup.export_recovery"),
        presentation_stale: false,
        payload: Ok(AsyncActionPayload::StartupExportRecovery {
            generation: app.startup_background.generation,
        }),
    });

    assert!(app.exit_requested);
    assert!(app.toast.is_none());
    assert!(app.agent_runner.is_none());
    assert!(app.onboarding_snapshot.is_none());
}

#[test]
fn exit_rejects_every_late_startup_stage_completion() {
    use crate::tui::async_action::{
        AsyncActionId, AsyncActionKind, AsyncActionPayload, AsyncActionResult,
    };

    let (lifecycle, mut lifecycle_requests) = cockpit_client::LifecycleClient::channel(1);
    let (connections, _connection_requests) = tokio::sync::mpsc::channel(1);
    let (sensitive, _sensitive_requests) = tokio::sync::mpsc::channel(1);
    let selected = crate::tui::agent_runner::SelectedLifecycle {
        endpoint: cockpit_client::ClientEndpoint::InProcess(
            cockpit_client::InProcessEndpoint::new(connections, sensitive),
        ),
        lifetime_client: None,
        owns_daemon: true,
        ephemeral_owner: false,
        socket: std::path::PathBuf::from("late-owner.sock"),
        startup_notice: None,
        promoted_from_ephemeral: false,
    };
    let mut app = App::new_composed_with_session_mode(
        None,
        false,
        cockpit_proto::SessionEntryMode::Code,
        super::StartupWorkspaceTrust::Decided,
        None,
        lifecycle,
    );
    let generation = app.startup_background.generation;
    let original_cwd = app.launch.cwd.clone();
    app.exit_requested = true;
    let result = |id, kind, payload| AsyncActionResult {
        id: AsyncActionId::from_raw_for_test(id),
        kind,
        presentation_stale: false,
        payload: Ok(payload),
    };

    app.apply_async_action_result(result(
        91,
        AsyncActionKind::Blocking("startup.lifetime-policy"),
        AsyncActionPayload::StartupLifetimePolicy {
            generation,
            result: Ok(false),
        },
    ));
    app.apply_async_action_result(result(
        92,
        AsyncActionKind::Internal("startup.lifecycle"),
        AsyncActionPayload::StartupLifecycleResolved {
            generation,
            result: Ok(selected),
        },
    ));
    app.apply_async_action_result(result(
        93,
        AsyncActionKind::DaemonRpc("onboarding.bootstrap"),
        AsyncActionPayload::StartupOnboardingBootstrap {
            generation,
            request_id: "late-bootstrap".into(),
            receipt: None,
            snapshot: Some(startup_snapshot(2)),
        },
    ));
    app.apply_async_action_result(result(
        94,
        AsyncActionKind::DaemonRpc("assistant.resolve"),
        AsyncActionPayload::StartupAssistantSessionResolved {
            generation,
            result: Ok(uuid::Uuid::now_v7()),
        },
    ));
    let late_workspace = std::path::PathBuf::from("late-workspace");
    app.apply_async_action_result(result(
        95,
        AsyncActionKind::DaemonRpc("startup.workspace"),
        AsyncActionPayload::StartupWorkspace(super::StartupWorkspaceCompletion {
            generation,
            opened: late_workspace.clone(),
            root: cockpit_config::trust::TrustRoot {
                opened_path: late_workspace.clone(),
                root: late_workspace,
                kind: cockpit_config::trust::TrustRootKind::Directory,
            },
            mode: Some(cockpit_proto::WorkspaceTrustMode::Trust),
            config_generation: 8,
            snapshot: Some(startup_snapshot(3)),
        }),
    ));

    assert!(!app.ephemeral_preference);
    assert!(app.startup_lifecycle.is_none());
    assert!(app.onboarding_snapshot.is_none());
    assert_eq!(app.launch.cwd, original_cwd);
    assert!(app.launch.session_id.is_none());
    assert!(app.toast.is_none());
    assert!(lifecycle_requests.try_recv().is_err());

    app.pending_startup_onboarding_operations.insert(
        AsyncActionId::from_raw_for_test(96),
        "late-onboarding".into(),
    );
    app.apply_async_action_result(AsyncActionResult {
        id: AsyncActionId::from_raw_for_test(96),
        kind: AsyncActionKind::DaemonRpc("onboarding.transition"),
        presentation_stale: false,
        payload: Err("late onboarding failure".to_string()),
    });
    assert!(app.toast.is_none());
}

#[test]
fn onboarding_completion_requires_matching_generation_operation_and_receipt() {
    use crate::tui::async_action::{
        AsyncActionId, AsyncActionKind, AsyncActionPayload, AsyncActionResult,
    };

    let mut app = App::new(None, false);
    app.startup_background.workspace_ready = true;
    app.onboarding_skip = true;
    app.onboarding_snapshot = Some(startup_snapshot(1));
    let receipt = cockpit_proto::OnboardingTransitionReceipt {
        run_id: uuid::Uuid::from_u128(11),
        attempt_id: uuid::Uuid::from_u128(12),
        consumed_revision: 1,
        receipt_id: uuid::Uuid::from_u128(13),
        status: cockpit_proto::OnboardingReceiptStatus::Committed,
    };
    let mut next = startup_snapshot(2);
    next.last_receipt = Some(receipt.clone());
    let completion = |generation,
                      expected_revision,
                      request_id: &str,
                      receipt: Option<cockpit_proto::OnboardingTransitionReceipt>,
                      snapshot|
     -> AsyncActionResult {
        AsyncActionResult {
            id: AsyncActionId::from_raw_for_test(1),
            kind: AsyncActionKind::DaemonRpc("onboarding.transition"),
            presentation_stale: false,
            payload: Ok(AsyncActionPayload::StartupOnboardingTransition(
                super::StartupOnboardingCompletion {
                    generation,
                    run_id: uuid::Uuid::from_u128(11),
                    attempt_id: uuid::Uuid::from_u128(12),
                    expected_revision,
                    request_id: request_id.into(),
                    receipt,
                    snapshot: Some(snapshot),
                },
            )),
        }
    };

    app.pending_startup_onboarding_operations.insert(
        AsyncActionId::from_raw_for_test(1),
        "expected-operation".into(),
    );
    app.apply_async_action_result(completion(
        99,
        1,
        "expected-operation",
        Some(receipt.clone()),
        next.clone(),
    ));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 1);
    app.pending_startup_onboarding_operations.insert(
        AsyncActionId::from_raw_for_test(1),
        "expected-operation".into(),
    );
    app.apply_async_action_result(completion(
        1,
        0,
        "expected-operation",
        Some(receipt.clone()),
        next.clone(),
    ));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 1);
    app.pending_startup_onboarding_operations.insert(
        AsyncActionId::from_raw_for_test(1),
        "expected-operation".into(),
    );
    app.apply_async_action_result(completion(
        1,
        1,
        "different-operation",
        Some(receipt.clone()),
        next.clone(),
    ));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 1);
    let mut wrong_receipt_snapshot = next.clone();
    wrong_receipt_snapshot.last_receipt = None;
    app.pending_startup_onboarding_operations.insert(
        AsyncActionId::from_raw_for_test(1),
        "expected-operation".into(),
    );
    app.apply_async_action_result(completion(
        1,
        1,
        "expected-operation",
        Some(receipt.clone()),
        wrong_receipt_snapshot,
    ));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 1);
    app.pending_startup_onboarding_operations.insert(
        AsyncActionId::from_raw_for_test(1),
        "expected-operation".into(),
    );
    app.apply_async_action_result(completion(
        1,
        1,
        "expected-operation",
        Some(receipt.clone()),
        next,
    ));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 2);
    app.apply_async_action_result(completion(
        1,
        1,
        "expected-operation",
        Some(receipt),
        startup_snapshot(3),
    ));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 2);
}

#[test]
fn pre_session_submission_retains_one_id_and_replacement_cannot_consume_it() {
    let mut app = App::new(None, false);
    app.first_paint_completed = true;
    app.composer.insert_str("keep this draft");
    assert!(!app.submit_input());
    let first = app.startup_retained_submission_id.unwrap();
    assert!(!app.submit_input());
    assert_eq!(app.startup_retained_submission_id, Some(first));
    assert!(app.agent_runner.is_none());

    app.startup_background.generation += 1;
    assert!(!app.submit_input());
    let replacement = app.startup_retained_submission_id.unwrap();
    assert_ne!(first.0, replacement.0);
    assert_ne!(first.1, replacement.1);
    assert_eq!(app.composer.display_text(), "keep this draft");
    assert!(app.agent_runner.is_none());
}

#[test]
fn retained_submission_dispatches_exactly_once_after_runner_attach() {
    use crate::tui::agent_runner::AgentRunner;
    use tokio::sync::mpsc;

    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(cockpit.join("config.json"), "{}").unwrap();
    let provider_dir = cockpit.join("providers");
    std::fs::create_dir(&provider_dir).unwrap();
    std::fs::write(
        provider_dir.join("p.json"),
        r#"{"url":"https://example.test","models":[{"id":"m"}]}"#,
    )
    .unwrap();

    let mut app = App::new_with_bootstrap_config(Some(tmp.path()), false);
    app.first_paint_completed = true;
    app.startup_background.started = true;
    app.launch.active_model = Some(("p".to_string(), "m".to_string()));
    app.config_snapshot.providers.providers.insert(
        "p".to_string(),
        cockpit_config::providers::ProviderEntry {
            url: "https://example.test".to_string(),
            models: vec![cockpit_config::providers::ModelEntry {
                id: "m".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    app.composer.insert_str("keep this draft");
    assert!(!app.submit_input());
    let (generation, retained_id) = app.startup_retained_submission_id.unwrap();
    assert_eq!(generation, app.startup_background.generation);

    app.startup_background.workspace_ready = true;
    app.startup_lifecycle = Some(App::stub_startup_lifecycle_for_tests());
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.adopt_runner(Ok(AgentRunner::stub_with_control_tx(control_tx)));

    assert!(app.startup_retained_submission_id.is_none());
    assert_eq!(
        app.history
            .iter()
            .filter(|entry| matches!(
                entry,
                super::HistoryEntry::User {
                    optimistic_submission_id: Some(id),
                    ..
                } if *id == retained_id
            ))
            .count(),
        1
    );

    let (control_tx, _control_rx) = mpsc::channel(4);
    app.adopt_runner(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    assert_eq!(
        app.history
            .iter()
            .filter(|entry| matches!(
                entry,
                super::HistoryEntry::User {
                    optimistic_submission_id: Some(id),
                    ..
                } if *id == retained_id
            ))
            .count(),
        1
    );
}

#[test]
fn sibling_runner_and_slash_paths_block_before_workspace_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.first_paint_completed = true;
    app.startup_background.started = true;

    app.composer.set("/init".to_string());
    assert!(!app.complete_or_submit());
    assert!(app.agent_runner.is_none());
    assert_eq!(app.composer.text(), "/init");

    app.composer.set("/compact".to_string());
    assert!(!app.complete_or_submit());
    assert!(app.agent_runner.is_none());
    assert!(app.pending_runner_attach.is_none());

    app.composer.set("/assistant demo".to_string());
    assert!(!app.complete_or_submit());
    assert!(app.async_actions.pending_count() == 0);

    app.composer.set("!pwd".to_string());
    assert!(!app.complete_or_submit());
    assert!(app.async_actions.pending_count() == 0);

    app.open_scratchpad_pane();
    assert!(!matches!(app.overlay, super::Overlay::Notes(_)));
    assert_eq!(app.async_actions.pending_count(), 0);

    app.composer.set("@src".to_string());
    app.reset_at_window();
    assert!(!app.at_suggestions_loading);
    assert_eq!(app.async_actions.pending_count(), 0);
}

#[test]
fn debug_last_message_defers_activation_until_trust_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.set_startup_debug_last_message(true);
    app.first_paint_completed = true;
    let unset_before = cockpit_core::engine::model::debug_last_message_path_for_tests().is_none();
    let snapshot = startup_snapshot(3);
    let root = cockpit_config::trust::TrustRoot {
        opened_path: tmp.path().to_path_buf(),
        root: tmp.path().to_path_buf(),
        kind: cockpit_config::trust::TrustRootKind::Directory,
    };

    app.apply_startup_workspace_completion(super::StartupWorkspaceCompletion {
        generation: app.startup_background.generation,
        opened: tmp.path().to_path_buf(),
        root,
        mode: Some(cockpit_proto::WorkspaceTrustMode::Trust),
        config_generation: 1,
        snapshot: Some(snapshot),
    });

    assert!(app.startup_background.workspace_ready);
    if unset_before {
        assert_eq!(
            cockpit_core::engine::model::debug_last_message_path_for_tests(),
            Some(tmp.path().join(".lastmessage").as_path())
        );
    } else {
        assert!(cockpit_core::engine::model::debug_last_message_path_for_tests().is_some());
    }
    cockpit_config::trust::clear_runtime_policy_for_tests();
}

#[test]
fn unset_daemon_trust_keeps_project_and_session_unavailable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.first_paint_completed = true;
    let snapshot = startup_snapshot(7);
    let root = cockpit_config::trust::TrustRoot {
        opened_path: tmp.path().to_path_buf(),
        root: tmp.path().to_path_buf(),
        kind: cockpit_config::trust::TrustRootKind::Directory,
    };

    app.apply_startup_workspace_completion(super::StartupWorkspaceCompletion {
        generation: app.startup_background.generation,
        opened: tmp.path().to_path_buf(),
        root,
        mode: None,
        config_generation: 11,
        snapshot: Some(snapshot),
    });

    assert!(!app.startup_background.workspace_ready);
    assert!(app.startup_pending_trust.is_some());
    assert_eq!(
        app.startup_modal_on_top(),
        Some(super::StartupModal::WorkspaceTrust)
    );
    assert!(app.onboarding_snapshot.is_none());
    assert!(app.agent_runner.is_none());
    assert!(!app.config_snapshot.from_daemon);
    assert_eq!(app.config_snapshot.generation, 11);
    cockpit_config::trust::clear_runtime_policy_for_tests();
}

#[tokio::test]
async fn every_shell_entry_keeps_lifecycle_pending_behind_policy() {
    let (lifecycle, mut requests) = cockpit_client::LifecycleClient::channel(8);
    let session_id = uuid::Uuid::now_v7();
    let mut entries = vec![
        App::new_composed_with_session_mode(
            None,
            false,
            cockpit_proto::SessionEntryMode::Code,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session_mode(
            None,
            false,
            cockpit_proto::SessionEntryMode::Computer,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session_mode(
            None,
            false,
            cockpit_proto::SessionEntryMode::Assistant,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session_mode(
            None,
            false,
            cockpit_proto::SessionEntryMode::Code,
            super::StartupWorkspaceTrust::Decided,
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_named_assistant(
            None,
            false,
            "named".to_string(),
            None,
            lifecycle.clone(),
        ),
        App::new_composed_with_session(
            None,
            false,
            super::StartupWorkspaceTrust::Decided,
            session_id,
            None,
            lifecycle,
        ),
    ];
    entries[3].configure_onboarding_launch(false, true);

    for app in &mut entries {
        app.first_paint_completed = true;
        app.start_startup_background_tasks_with_policy(std::future::pending());
    }
    tokio::task::yield_now().await;

    assert!(requests.try_recv().is_err());
    for app in entries {
        assert_eq!(app.async_actions.pending_count(), 1);
        assert!(app.startup_lifecycle.is_none());
        assert!(!app.startup_background.workspace_ready);
        assert!(app.agent_runner.is_none());
    }
}
