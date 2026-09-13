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
    entries[0].configure_onboarding_launch(false, true);

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

async fn run_startup_trace_case(background_agents: bool, resolution_ephemeral: bool) -> String {
    let namespace = tempfile::tempdir().unwrap();
    for name in ["config", "data", "state", "runtime", "workspace"] {
        std::fs::create_dir(namespace.path().join(name)).unwrap();
    }
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
        Some(&namespace.path().join("workspace")),
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
    let onboarding_notify = app.async_actions.notifier();
    let onboarding_completion = onboarding_notify.notified();
    request
        .reply
        .send(Ok(cockpit_client::LifecycleResolution {
            endpoint,
            owns_daemon: background_agents,
            ephemeral_owner: resolution_ephemeral,
            socket: namespace.path().join("runtime/fake-owner.sock"),
            startup_notice: None,
            promoted_from_ephemeral: false,
        }))
        .unwrap();
    onboarding_completion.await;
    let workspace_notify = app.async_actions.notifier();
    let workspace_completion = workspace_notify.notified();
    assert!(app.drain_async_actions());
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
        !output.contains(&namespace.path().display().to_string()),
        "startup trace leaked its temporary namespace: {output}"
    );
    output
}

#[tokio::test(flavor = "current_thread")]
async fn startup_trace_harness_orders_default_and_configured_false_without_real_services() {
    for trace in [
        run_startup_trace_case(true, false).await,
        run_startup_trace_case(false, true).await,
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
        assert!(!trace.contains("fake-owner.sock"));
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
fn onboarding_completion_requires_matching_generation_run_and_revision() {
    use crate::tui::async_action::{
        AsyncActionId, AsyncActionKind, AsyncActionPayload, AsyncActionResult,
    };

    let mut app = App::new(None, false);
    app.startup_background.workspace_ready = true;
    app.onboarding_skip = true;
    app.onboarding_snapshot = Some(startup_snapshot(1));
    let completion = |generation, expected_revision, snapshot| AsyncActionResult {
        id: AsyncActionId::from_raw_for_test(1),
        kind: AsyncActionKind::DaemonRpc("onboarding.transition"),
        presentation_stale: false,
        payload: Ok(AsyncActionPayload::StartupOnboardingTransition(
            super::StartupOnboardingCompletion {
                generation,
                run_id: uuid::Uuid::from_u128(11),
                attempt_id: uuid::Uuid::from_u128(12),
                expected_revision,
                snapshot: Some(snapshot),
            },
        )),
    };

    app.apply_async_action_result(completion(99, 1, startup_snapshot(2)));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 1);
    app.apply_async_action_result(completion(1, 0, startup_snapshot(2)));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 1);
    app.apply_async_action_result(completion(1, 1, startup_snapshot(2)));
    assert_eq!(app.onboarding_snapshot.as_ref().unwrap().revision, 2);
    app.apply_async_action_result(completion(1, 1, startup_snapshot(3)));
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
