use super::{App, HistoryEntry};
use crate::tui::agent_runner::AgentRunner;
use cockpit_client::submission::ClientUserSubmission;
use std::fs;
use tokio::sync::mpsc;

fn selection(provider: &str, model: &str) -> cockpit_config::providers::ActiveModelRef {
    cockpit_config::providers::ActiveModelRef {
        provider: provider.to_string(),
        model: model.to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    }
}

fn seed_model_selection_retry(app: &mut App, retry: super::ModelSelectionRetry) {
    let session_id = retry.session_id;
    app.retry_model_selections.insert(session_id, retry);
}

fn preference_bearing_selection(
    provider: &str,
    model: &str,
) -> cockpit_config::providers::ActiveModelRef {
    cockpit_config::providers::ActiveModelRef {
        provider: provider.to_string(),
        model: model.to_string(),
        reasoning_effort: Some(cockpit_config::providers::ActiveReasoningEffort {
            value: "high".to_string(),
        }),
        thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
        prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
    }
}

#[test]
fn passive_same_generation_terminal_result_corrects_default_and_divergence() {
    let mut app = App::new(None, false);
    let active = preference_bearing_selection("p", "selected");
    let old_default = selection("p", "old-default");
    app.apply_active_model_state(active.clone(), Some(old_default), true, 4);
    assert!(app.launch.active_model_diverged);
    assert!(app.config_drift.is_some());

    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id: uuid::Uuid::new_v4(),
            provider: active.provider.clone(),
            model: active.model.clone(),
            reasoning_effort: active
                .reasoning_effort
                .as_ref()
                .map(|effort| effort.value.clone()),
            thinking_mode: active.thinking_mode,
            prompt_cache_retention: active.prompt_cache_retention,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: active.clone(),
                    default_selection: Some(active.clone()),
                    diverged: false,
                    generation: 4,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::Verified {
                    selection: cockpit_config::providers::ActiveModelRef {
                        provider: "provider-b".into(),
                        model: "model-b".into(),
                        reasoning_effort: None,
                        thinking_mode: None,
                        prompt_cache_retention: None,
                    },
                    generation: 1,
                    scope_label: "user".into(),
                    unchanged: false,
                },
            },
        },
    );

    assert_eq!(app.active_model_selection, Some(active.clone()));
    assert_eq!(
        app.launch.active_model,
        Some(("p".into(), "selected".into()))
    );
    assert_eq!(app.launch.provider_line, "p / selected");
    assert!(!app.launch.active_model_diverged);
    assert!(app.config_drift.is_none());
    assert_eq!(app.active_model_state_generation, 4);
    assert!(app.pending_model_selection.is_none());

    let older = selection("p", "older-event");
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id: uuid::Uuid::new_v4(),
            provider: older.provider.clone(),
            model: older.model.clone(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: older.clone(),
                    default_selection: Some(older),
                    diverged: false,
                    generation: 3,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::NotRequested,
            },
        },
    );
    assert_eq!(app.active_model_selection, Some(active));
    assert_eq!(app.active_model_state_generation, 4);
}

fn write_config(path: &std::path::Path) {
    fs::write(path, r#"{"providers":{"p":{}}}"#).unwrap();
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(path, "p").unwrap();
    fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    fs::write(
        provider_path,
        r#"{"url":"https://example.test","models":[{"id":"a"}]}"#,
    )
    .unwrap();
}

fn exact_queued_submission() -> super::QueuedModelSubmission {
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([1, 2, 3, 255]),
    ))
    .write_to(&mut png, image::ImageFormat::Png)
    .unwrap();
    let tag = cockpit_proto::TagExpansionMeta {
        tool: "read".to_string(),
        path: "src/model.rs".to_string(),
        detail: "selected lines".to_string(),
        ok: true,
    };
    super::QueuedModelSubmission {
        client_submission_id: uuid::Uuid::new_v4(),
        composer_text: "review @src/model.rs with image".to_string(),
        display: "review @src/model.rs with image".to_string(),
        submission: ClientUserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: cockpit_client::submission::UserSubmissionKind::Compact,
            origin: Default::default(),
            text: "review expanded source\n\n<image>".to_string(),
            display_text: Some("review @src/model.rs with image".to_string()),
            tag_expansions: vec![tag.clone()],
            images: vec![cockpit_client::image_upload::SubmissionImage::png(
                png.into_inner(),
            )],
            media: Vec::new(),
            forced_skill: Some("review".to_string()),
            origin_principal: Some("flycockpit:test-user".to_string()),
            job_id: Some("job-1".to_string()),
            preflight_cleaned: Some("review expanded source".to_string()),
            queue_item_ids: vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
            client_submissions: Vec::new(),
            pending_terminal_disposition: None,
            run_invocation_id: None,
            queue_target: Some(cockpit_proto::QueueTarget {
                id: "target-1".to_string(),
                agent: "Build".to_string(),
                depth: 1,
                task_call_id: Some("task-1".to_string()),
            }),
            delivery_class: Default::default(),
            delivery_class_override: None,
        },
        tag_expansions: vec![tag],
    }
}

fn queued_submission_value(queued: &super::QueuedModelSubmission) -> serde_json::Value {
    serde_json::json!({
        "composer_text": &queued.composer_text,
        "display": &queued.display,
        "submission": &queued.submission,
        "tag_expansions": &queued.tag_expansions,
    })
}

fn install_pending_model_submission(
    app: &mut App,
    session_id: uuid::Uuid,
    selection_id: uuid::Uuid,
    requested: cockpit_config::providers::ActiveModelRef,
    minimum_generation: u64,
    queued: super::QueuedModelSubmission,
) {
    let order_sequence = app
        .submission_order
        .enqueue(crate::tui::structured_paste::OrderedIntent::ModelSwitch(
            selection_id,
        ))
        .unwrap();
    let fence_sequence = app
        .submission_order
        .enqueue(crate::tui::structured_paste::OrderedIntent::Fence(
            queued.client_submission_id,
        ))
        .unwrap();
    app.submission_fences.insert(
        queued.client_submission_id,
        crate::tui::structured_paste::SubmissionFenceV1 {
            client_submission_id: queued.client_submission_id,
            fence_sequence,
            host: crate::tui::structured_paste::HostIdentity {
                client_instance_id: app.paste_client_instance_id,
                connection_epoch: 0,
                session_id,
                terminal_generation: app.terminal_input_generation.unwrap_or_default(),
            },
            view_generation: app.config_snapshot.generation,
            source_draft_generation: app.draft_generation,
            created_at: app.monotonic_origin.elapsed(),
            captured_composer: queued.composer_text.clone(),
            accepted_tags: Vec::new(),
            pending_git_blocks: Vec::new(),
            model: crate::tui::structured_paste::CapturedModel {
                provider_id: requested.provider.clone(),
                model_id: requested.model.clone(),
                active_model_state_generation: minimum_generation,
                image_capability_generation: app.config_snapshot.generation,
                supports_images: true,
            },
            assembled_wire_digest: None,
            slots: Vec::new(),
            retained_drafts: Vec::new(),
            lifecycle: crate::tui::structured_paste::FenceLifecycle::Ready,
        },
    );
    app.pending_model_selection = Some(super::PendingModelSelection {
        order_sequence,
        session_id: Some(session_id),
        selection_id,
        requested,
        trigger: cockpit_proto::ActiveModelSwitchTrigger::Quick,
        minimum_generation,
        started_at: std::time::Instant::now(),
        queued_submission: Some(queued),
    });
}

#[test]
fn terminal_daemon_link_preserves_full_pending_selection_and_exact_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, _control_rx) = mpsc::channel(4);
    let runner = AgentRunner::stub_with_control_tx(control_tx);
    app.launch.session_id = Some(runner.session_id());
    app.agent_runner = Some(Ok(runner));
    let requested = preference_bearing_selection("p", "a");
    assert!(app.request_model_selection(
        "/model",
        requested.clone(),
        false,
        cockpit_proto::ActiveModelSwitchTrigger::Picker,
    ));
    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    app.pending_model_selection
        .as_mut()
        .unwrap()
        .queued_submission = Some(queued);
    assert!(
        app.pending_control_requests
            .values()
            .any(|request| matches!(
                request.applied,
                super::ControlApplied::ModelSelection { .. }
            ))
    );

    app.apply_event(
        cockpit_client::presentation::TurnEvent::DaemonLinkTerminal {
            error: "protocol link ended".to_string(),
        },
    );

    assert!(app.pending_model_selection.is_none());
    assert!(
        !app.pending_control_requests
            .values()
            .any(|request| matches!(
                request.applied,
                super::ControlApplied::ModelSelection { .. }
            ))
    );
    let retry = app
        .current_model_selection_retry()
        .expect("terminal link preserves retry state");
    assert_eq!(retry.requested, requested);
    assert_eq!(
        retry.trigger,
        cockpit_proto::ActiveModelSwitchTrigger::Picker
    );
    assert_eq!(
        queued_submission_value(
            retry
                .queued_submission
                .as_ref()
                .expect("terminal link preserves exact queued submission")
        ),
        expected_queued
    );
}

#[test]
fn quick_model_change_waits_for_terminal_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));

    app.active_model_selection = Some(cockpit_config::providers::ActiveModelRef {
        provider: "old-provider".to_string(),
        model: "old-model".to_string(),
        reasoning_effort: Some(cockpit_config::providers::ActiveReasoningEffort {
            value: "high".to_string(),
        }),
        thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
        prompt_cache_retention: Some(cockpit_config::providers::PromptCacheRetention::Extended),
    });
    app.apply_quick_commit(crate::tui::quick_dialog::QuickCommit {
        active_model: Some(("p".to_string(), "a".to_string())),
        ..Default::default()
    });

    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("quick model selection is pending")
        .selection_id;
    let request = control_rx.try_recv().expect("quick request");
    match request.request {
        cockpit_proto::Request::SetActiveModel {
            selection_id: actual,
            persist_as_default,
            trigger,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
            ..
        } => {
            assert_eq!(actual, selection_id);
            assert_eq!(reasoning_effort.as_deref(), Some("high"));
            assert_eq!(
                thinking_mode,
                Some(cockpit_config::providers::ThinkingMode::High)
            );
            assert_eq!(
                prompt_cache_retention,
                Some(cockpit_config::providers::PromptCacheRetention::Extended)
            );
            assert!(!persist_as_default);
            assert_eq!(trigger, cockpit_proto::ActiveModelSwitchTrigger::Quick);
        }
        other => panic!("expected SetActiveModel, got {other:?}"),
    }
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("control request pending");
    app.apply_control_request_outcome(
        request_id,
        cockpit_client::presentation::ControlRequestOutcome::Applied,
    );
    assert!(
        !app.history.iter().any(
            |entry| matches!(entry, HistoryEntry::Plain { line } if line.contains("active model is now"))
        ),
        "queue acceptance must not be presented as model-switch success"
    );

    let confirmed = selection("p", "a");
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: confirmed.provider.clone(),
            model: confirmed.model.clone(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: confirmed,
                    default_selection: None,
                    diverged: true,
                    generation: 1,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::NotRequested,
            },
        },
    );

    assert!(app.pending_model_selection.is_none());
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line == "Using p/a for this session.")
    );
}

#[test]
fn transport_send_failure_retains_complete_queued_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, control_rx) = mpsc::channel(1);
    drop(control_rx);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let queued = exact_queued_submission();
    let expected = queued_submission_value(&queued);
    let session_id = app.launch.session_id;
    seed_model_selection_retry(
        &mut app,
        super::ModelSelectionRetry {
            session_id,
            requested: selection("p", "a"),
            trigger: cockpit_proto::ActiveModelSwitchTrigger::Quick,
            queued_submission: Some(queued),
        },
    );

    assert!(!app.request_model_selection(
        "/quick",
        selection("p", "a"),
        false,
        cockpit_proto::ActiveModelSwitchTrigger::Quick,
    ));

    assert!(app.pending_model_selection.is_none());
    assert!(app.pending_control_requests.is_empty());
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("send failure retains queued payload"),
        ),
        expected
    );
}

fn assert_control_failure_retains_complete_submission(
    outcome: cockpit_client::presentation::ControlRequestOutcome,
) {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, mut control_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    let queued = exact_queued_submission();
    let expected = queued_submission_value(&queued);
    let session_id = app.launch.session_id;
    seed_model_selection_retry(
        &mut app,
        super::ModelSelectionRetry {
            session_id,
            requested: selection("p", "a"),
            trigger: cockpit_proto::ActiveModelSwitchTrigger::Quick,
            queued_submission: Some(queued),
        },
    );
    assert!(app.request_model_selection(
        "/quick",
        selection("p", "a"),
        false,
        cockpit_proto::ActiveModelSwitchTrigger::Quick,
    ));
    control_rx
        .try_recv()
        .expect("control request was delivered");
    let request_id = *app
        .pending_control_requests
        .keys()
        .next()
        .expect("control request is pending");

    app.apply_control_request_outcome(request_id, outcome);

    assert!(app.pending_model_selection.is_none());
    assert!(app.pending_control_requests.is_empty());
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("control failure retains queued payload"),
        ),
        expected
    );
}

#[test]
fn rejected_ack_retains_complete_queued_submission() {
    assert_control_failure_retains_complete_submission(
        cockpit_client::presentation::ControlRequestOutcome::Rejected("busy".to_string()),
    );
}

#[test]
fn not_delivered_ack_retains_complete_queued_submission() {
    assert_control_failure_retains_complete_submission(
        cockpit_client::presentation::ControlRequestOutcome::NotDelivered(
            cockpit_client::presentation::ControlRequestNotDelivered::RunnerTeardown,
        ),
    );
}

#[test]
fn failed_cleanup_does_not_overwrite_an_already_preserved_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    let preserved = exact_queued_submission();
    let expected = queued_submission_value(&preserved);
    let original_requested = selection("original", "selection");
    let session_id = app.launch.session_id;
    seed_model_selection_retry(
        &mut app,
        super::ModelSelectionRetry {
            session_id,
            requested: original_requested.clone(),
            trigger: cockpit_proto::ActiveModelSwitchTrigger::Cycle,
            queued_submission: Some(preserved),
        },
    );
    let mut later = exact_queued_submission();
    later.submission.text = "later payload".to_string();
    let pending = super::PendingModelSelection {
        order_sequence: 0,
        session_id: app.launch.session_id,
        selection_id: uuid::Uuid::new_v4(),
        requested: selection("p", "a"),
        trigger: cockpit_proto::ActiveModelSwitchTrigger::Quick,
        minimum_generation: 0,
        started_at: std::time::Instant::now(),
        queued_submission: Some(later),
    };

    app.preserve_failed_model_selection(pending);

    assert_eq!(
        app.current_model_selection_retry().unwrap().requested,
        original_requested
    );
    assert_eq!(
        queued_submission_value(
            app.current_model_selection_retry()
                .and_then(|retry| retry.queued_submission.as_ref())
                .expect("original retry remains present"),
        ),
        expected
    );
}

#[test]
fn confirmed_model_release_queue_full_retains_and_retries_exact_draft() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    let (control_tx, _control_rx) = mpsc::channel(2);
    let (input_tx, mut input_rx) = mpsc::channel(1);
    input_tx
        .try_send(ClientUserSubmission::text("channel blocker").into())
        .unwrap();
    let runner = AgentRunner::stub_with_channels(control_tx, input_tx);
    let session_id = runner.session_id();
    app.launch.session_id = Some(session_id);
    app.agent_runner = Some(Ok(runner));

    let queued = exact_queued_submission();
    app.composer.set(queued.composer_text.clone());
    let requested = preference_bearing_selection("p", "a");
    let mut expected_submission = queued.submission.clone();
    expected_submission.expected_model_state_generation = Some(1);
    expected_submission.expected_model = Some(requested.clone());
    let expected = serde_json::to_value(expected_submission).unwrap();
    let selection_id = uuid::Uuid::new_v4();
    install_pending_model_submission(
        &mut app,
        session_id,
        selection_id,
        requested.clone(),
        0,
        queued,
    );

    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: requested.provider.clone(),
            model: requested.model.clone(),
            reasoning_effort: requested
                .reasoning_effort
                .as_ref()
                .map(|effort| effort.value.clone()),
            thinking_mode: requested.thinking_mode,
            prompt_cache_retention: requested.prompt_cache_retention,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: requested.clone(),
                    default_selection: Some(requested),
                    diverged: false,
                    generation: 1,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::NotRequested,
            },
        },
    );

    assert!(app.pending_model_selection.is_none());
    assert!(app.composer.is_empty());
    assert_eq!(app.retained_pre_dispatch_submissions.len(), 1);
    assert_eq!(
        serde_json::to_value(&app.retained_pre_dispatch_submissions[0].pending.submission).unwrap(),
        expected
    );

    let _blocker = input_rx.try_recv().expect("free input capacity");
    assert!(app.retry_retained_pre_dispatch_submissions());
    let crate::tui::agent_runner::RunnerInput::Submission(delivered) =
        input_rx.try_recv().expect("held draft retry delivered")
    else {
        panic!("one held draft should use one submission input");
    };
    assert_eq!(delivered.intended_session_id, session_id);
    assert_eq!(
        serde_json::to_value(delivered.submission).unwrap(),
        expected
    );
}

#[test]
fn second_submit_waiting_on_model_preserves_all_unconsumed_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;

    let held = exact_queued_submission();
    let expected_held = queued_submission_value(&held);
    app.pending_model_selection = Some(super::PendingModelSelection {
        order_sequence: 0,
        session_id: Some(uuid::Uuid::new_v4()),
        selection_id: uuid::Uuid::new_v4(),
        requested: preference_bearing_selection("p", "a"),
        trigger: cockpit_proto::ActiveModelSwitchTrigger::Picker,
        minimum_generation: 0,
        started_at: std::time::Instant::now(),
        queued_submission: Some(held),
    });
    app.composer
        .set("second draft @path with spaces.rs".to_string());
    app.pending_git_blocks = vec!["git diff --binary".to_string(), "git status".to_string()];
    app.accepted_tags = vec!["path with spaces.rs".to_string()];
    let expected_git_blocks = app.pending_git_blocks.clone();
    let expected_tags = app.accepted_tags.clone();

    assert!(!app.submit_input());

    assert_eq!(app.composer.text(), "second draft @path with spaces.rs");
    assert_eq!(app.pending_git_blocks, expected_git_blocks);
    assert_eq!(app.accepted_tags, expected_tags);
    assert_eq!(
        queued_submission_value(
            app.pending_model_selection
                .as_ref()
                .and_then(|pending| pending.queued_submission.as_ref())
                .expect("the first complete payload remains held"),
        ),
        expected_held
    );
}

#[test]
fn chrome_renders_session_derived_active_model() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    write_config(&cockpit.join("config.json"));

    let mut app = App::new(Some(tmp.path()), false);
    app.apply_event(cockpit_client::presentation::TurnEvent::ActiveModelState {
        selection: selection("p", "a"),
        default_selection: Some(selection("other", "old")),
        diverged: true,
        generation: 2,
    });

    assert_eq!(
        app.launch.active_model,
        Some(("p".to_string(), "a".to_string()))
    );
    assert!(app.launch.active_model_diverged);

    app.apply_event(cockpit_client::presentation::TurnEvent::ActiveModelState {
        selection: selection("stale", "stale"),
        default_selection: None,
        diverged: false,
        generation: 1,
    });

    assert_eq!(
        app.launch.active_model,
        Some(("p".to_string(), "a".to_string()))
    );
    assert!(app.launch.active_model_diverged);
}

#[test]
fn config_drift_state_retains_config_model_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    write_config(&cockpit.join("config.json"));

    let mut app = App::new(Some(tmp.path()), false);
    app.apply_event(cockpit_client::presentation::TurnEvent::ActiveModelState {
        selection: selection("session-p", "session-m"),
        default_selection: Some(selection("config-p", "config-m")),
        diverged: true,
        generation: 2,
    });

    let drift = app.config_drift.as_ref().expect("drift state retained");
    assert_eq!(drift.config_label(), "config-p/config-m");
    assert_eq!(app.session_model_label(), "session-p/session-m");
}

enum ModelEpochPath {
    AdoptReplacement,
    AdoptSameSession,
    SameRunnerReconnect,
    EventStreamLagResync,
    SessionSwitch,
}

fn assert_runner_epoch_reset_and_followup_completion(path: ModelEpochPath) {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _runtime_guard = runtime.enter();
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;

    let old_session_id = uuid::Uuid::new_v4();
    let new_session_id = match path {
        ModelEpochPath::AdoptSameSession
        | ModelEpochPath::SameRunnerReconnect
        | ModelEpochPath::EventStreamLagResync => old_session_id,
        ModelEpochPath::AdoptReplacement | ModelEpochPath::SessionSwitch => uuid::Uuid::new_v4(),
    };
    let (control_tx, mut control_rx) = mpsc::channel(2);
    let (input_tx, mut input_rx) = mpsc::channel(2);
    let mut attached_runner = Some(AgentRunner::stub_with_channels(control_tx, input_tx));
    *attached_runner
        .as_ref()
        .unwrap()
        .session_id_state
        .lock()
        .unwrap() = new_session_id;
    let attached_selection = selection("attached-provider", "attached-model");
    let attached_state = cockpit_proto::ActiveModelState {
        selection: attached_selection.clone(),
        default_selection: Some(attached_selection.clone()),
        diverged: false,
        generation: 0,
    };
    attached_runner.as_mut().unwrap().active_model_state = Some(attached_state.clone());
    if matches!(
        path,
        ModelEpochPath::SameRunnerReconnect | ModelEpochPath::EventStreamLagResync
    ) {
        app.agent_runner = Some(Ok(attached_runner.take().unwrap()));
    } else {
        let (old_control_tx, _old_control_rx) = mpsc::channel(2);
        let old_runner = AgentRunner::stub_with_control_tx(old_control_tx);
        *old_runner.session_id_state.lock().unwrap() = old_session_id;
        app.agent_runner = Some(Ok(old_runner));
    }
    app.launch.session_id = Some(old_session_id);
    app.active_model_state_generation = 9;
    app.apply_active_model_state(
        selection("old-provider", "old-model"),
        Some(selection("old-provider", "old-model")),
        false,
        9,
    );

    let queued = exact_queued_submission();
    let expected_queued = queued_submission_value(&queued);
    let pending_requested = preference_bearing_selection("pending-provider", "pending-model");
    let mut expected_submission = queued.submission.clone();
    expected_submission.expected_model_state_generation = Some(1);
    expected_submission.expected_model = Some(pending_requested.clone());
    let expected_submission = serde_json::to_value(expected_submission).unwrap();
    app.composer.set(queued.composer_text.clone());
    let old_selection_id = uuid::Uuid::new_v4();
    install_pending_model_submission(
        &mut app,
        old_session_id,
        old_selection_id,
        pending_requested.clone(),
        9,
        queued,
    );
    app.pending_control_requests.insert(
        cockpit_client::presentation::ControlRequestId(77),
        super::PendingControlRequest::new(
            "/quick",
            super::ControlApplied::ModelSelection {
                selection_id: old_selection_id,
            },
        ),
    );

    let automatically_retried = matches!(
        path,
        ModelEpochPath::SameRunnerReconnect | ModelEpochPath::EventStreamLagResync
    );
    match path {
        ModelEpochPath::AdoptReplacement | ModelEpochPath::AdoptSameSession => {
            app.adopt_runner(Ok(attached_runner.take().unwrap()));
        }
        ModelEpochPath::SameRunnerReconnect => {
            app.apply_event(
                cockpit_client::presentation::TurnEvent::DaemonLinkReconnected {
                    active_model_state: Some(attached_state.clone()),
                },
            );
        }
        ModelEpochPath::EventStreamLagResync => {
            app.apply_event(
                cockpit_client::presentation::TurnEvent::DaemonLinkResynced {
                    active_model_state: Some(attached_state.clone()),
                },
            );
        }
        ModelEpochPath::SessionSwitch => {
            app.agent_runner.take();
            app.apply_session_switch_outcome(crate::tui::agent_runner::SessionSwitchOutcome {
                target: crate::tui::agent_runner::SessionTarget::Resume {
                    session_id: new_session_id,
                    since_seq: None,
                },
                session_id: new_session_id,
                session_entry_mode: cockpit_core::daemon::proto::SessionEntryMode::Computer,
                promoted_from_ephemeral: false,
                short_id: "new001".to_string(),
                active_agent: "Build".to_string(),
                active_agent_path: vec!["Build".to_string()],
                last_applied_seq: None,
                foreground_target: Some(cockpit_proto::QueueTarget::root("Build")),
                active_model_state: Some(attached_state.clone()),
                project_id: "project".to_string(),
                history: Vec::new(),
                paused_work: Vec::new(),
                repair_required: None,
                resume_compaction_offer: None,
                btw_fork: None,
                daemon_version: "test".to_string(),
                daemon_compatible: true,
                attachment_epoch: 0,
                transition_guard: None,
            });
            app.agent_runner = Some(Ok(attached_runner.take().unwrap()));
        }
    }

    assert_eq!(app.active_model_state_generation, 0);
    assert_eq!(
        app.active_model_selection.as_ref(),
        Some(&attached_selection)
    );
    assert_eq!(app.launch.session_id, Some(new_session_id));
    if matches!(path, ModelEpochPath::SessionSwitch) {
        assert_eq!(
            app.session_mode(),
            Some(cockpit_core::daemon::proto::SessionEntryMode::Computer),
            "the session-switch chrome must adopt the daemon-returned Computer setup"
        );
    }
    assert_eq!(app.pending_model_selection.is_some(), automatically_retried);
    assert!(!app.pending_control_requests.values().any(|request| {
        matches!(
            request.applied,
            super::ControlApplied::ModelSelection { selection_id }
                if selection_id == old_selection_id
        )
    }));
    assert_eq!(
        app.pending_control_requests.values().any(|request| {
            matches!(
                request.applied,
                super::ControlApplied::ModelSelection { .. }
            )
        }),
        automatically_retried
    );
    let preserved = if automatically_retried {
        let pending = app
            .pending_model_selection
            .as_ref()
            .expect("reconnect immediately retries the retained model intent");
        assert_eq!(pending.requested, pending_requested);
        pending
            .queued_submission
            .as_ref()
            .expect("automatic retry retains queued submission")
    } else {
        let retry = app
            .retry_model_selections
            .get(&Some(old_session_id))
            .expect("runner epoch change retains retry intent for its owning session");
        assert_eq!(retry.requested, pending_requested);
        retry
            .queued_submission
            .as_ref()
            .expect("runner epoch change retains queued submission")
    };
    assert_eq!(queued_submission_value(preserved), expected_queued);
    if old_session_id != new_session_id {
        assert!(app.current_model_selection_retry().is_none());
        assert!(app.request_model_selection(
            "/quick",
            pending_requested,
            false,
            cockpit_proto::ActiveModelSwitchTrigger::Quick,
        ));
        assert!(
            app.pending_model_selection
                .as_ref()
                .expect("replacement selection is pending")
                .queued_submission
                .is_none()
        );
        assert!(input_rx.try_recv().is_err());
        return;
    }
    let requested = pending_requested;
    if !automatically_retried {
        app.open_model_menu_highlighting(Some(&requested));
        assert!(app.composer_controls.picker.is_some());
        assert!(app.request_model_selection(
            "/quick",
            requested.clone(),
            false,
            cockpit_proto::ActiveModelSwitchTrigger::Quick,
        ));
    }
    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("follow-up selection is pending")
        .selection_id;
    assert_eq!(
        app.pending_model_selection
            .as_ref()
            .expect("follow-up selection is pending")
            .minimum_generation,
        0
    );
    control_rx.try_recv().expect("follow-up control delivered");

    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: requested.provider.clone(),
            model: requested.model.clone(),
            reasoning_effort: requested
                .reasoning_effort
                .as_ref()
                .map(|effort| effort.value.clone()),
            thinking_mode: requested.thinking_mode,
            prompt_cache_retention: requested.prompt_cache_retention,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: requested.clone(),
                    default_selection: Some(requested),
                    diverged: false,
                    generation: 1,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::NotRequested,
            },
        },
    );

    let delivered = input_rx
        .try_recv()
        .expect("generation-one result releases exact queued submission");
    assert_eq!(
        serde_json::to_value(delivered.submission.clone()).unwrap(),
        expected_submission
    );
    assert_eq!(app.active_model_state_generation, 1);
    assert!(app.pending_model_selection.is_none());
    assert!(app.current_model_selection_retry().is_none());
}

#[test]
fn session_replacement_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::AdoptReplacement);
}

#[test]
fn same_session_reconnect_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::AdoptSameSession);
}

#[test]
fn same_runner_daemon_reconnect_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::SameRunnerReconnect);
}

#[test]
fn event_stream_lag_resync_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::EventStreamLagResync);
}

#[test]
fn session_switch_outcome_starts_new_model_generation_epoch() {
    assert_runner_epoch_reset_and_followup_completion(ModelEpochPath::SessionSwitch);
}

#[test]
fn standalone_default_model_result_is_correlated_and_leaves_the_session_alone() {
    let mut app = App::new(None, false);
    let mine = uuid::Uuid::new_v4();
    app.pending_default_model_update_id = Some(mine);

    // A late result for a different operation is ignored entirely.
    app.apply_event(
        cockpit_client::presentation::TurnEvent::DefaultModelUpdateResult {
            default_update_id: uuid::Uuid::new_v4(),
            outcome: cockpit_proto::DefaultModelStandaloneOutcome::Applied {
                selection: Some(selection("other", "model")),
                generation: 1,
                authority_revision:
                    "4d8d4cd5bbf18d6ae07e52adf7f0b6a9e5e8f91a9e72d8cb69c6a129e84e400c".into(),
                scope_label: "user".into(),
                unchanged: false,
            },
        },
    );
    assert_eq!(app.pending_default_model_update_id, Some(mine));
    assert!(
        !app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("other/model")
        )),
        "a stale terminal event must not produce misleading feedback"
    );
    assert!(app.pending_model_selection.is_none());

    app.apply_event(
        cockpit_client::presentation::TurnEvent::DefaultModelUpdateResult {
            default_update_id: mine,
            outcome: cockpit_proto::DefaultModelStandaloneOutcome::Applied {
                selection: Some(selection("p", "a")),
                generation: 2,
                authority_revision:
                    "4d8d4cd5bbf18d6ae07e52adf7f0b6a9e5e8f91a9e72d8cb69c6a129e84e400c".into(),
                scope_label: "project".into(),
                unchanged: false,
            },
        },
    );
    assert_eq!(app.pending_default_model_update_id, None);
    assert!(
        app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line }
                if line.contains("Default model for new sessions set to p/a")
                    && line.contains("project")
        )),
        "history: {:?}",
        app.history
    );
    assert!(
        app.pending_model_selection.is_none(),
        "a Settings default update never creates session model intent"
    );

    // A rejection claims no change and names only a scope.
    let second = uuid::Uuid::new_v4();
    app.pending_default_model_update_id = Some(second);
    app.apply_event(
        cockpit_client::presentation::TurnEvent::DefaultModelUpdateResult {
            default_update_id: second,
            outcome: cockpit_proto::DefaultModelStandaloneOutcome::Rejected {
                user_message: "the highest-precedence config layer (project) is not writable"
                    .into(),
                diagnostic_code: "effective_default_target_unwritable".into(),
            },
        },
    );
    assert!(
        app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::Plain { line } if line.contains("Default model was not changed")
        )),
        "history: {:?}",
        app.history
    );
}
