use std::any::Any;

use super::super::pointer_actions::SettingsPointerAction;
use super::super::{SettingsDaemonEffectWork, SettingsPage, SettingsPointerSurfaceKind};
use super::*;
use cockpit_config::config::media_budget::MediaResourceLimits;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn test_dialog() -> crate::tui::settings::SettingsDialog {
    use tempfile::TempDir;
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    std::mem::forget(tmp);
    super::super::tests::open_fixture_dialog(&path)
}

fn render_page_lines(
    page: &dyn SettingsPage,
    dialog: &crate::tui::settings::SettingsDialog,
    width: u16,
    height: u16,
) -> Vec<String> {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    let cx: &SettingsCx = dialog;
    terminal
        .draw(|frame| {
            let area = frame.area();
            page.render(cx, frame, area);
        })
        .unwrap();
    let buffer = terminal.backend().buffer();
    buffer
        .content()
        .iter()
        .collect::<Vec<_>>()
        .chunks(width as usize)
        .map(|row| {
            row.iter()
                .map(|cell| cell.symbol().to_string())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

fn sample_trace(mode: SidecarModeChoice) -> SidecarEffectiveTrace {
    SidecarEffectiveTrace {
        primary: Some(SidecarPrimaryTrace {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            trust: "trusted".into(),
            location: "public_cloud".into(),
            credential_fingerprint: "abcd".repeat(8),
        }),
        matched_source: "trust_class_default".into(),
        sidecar_provider: Some("openai".into()),
        sidecar_model: Some("gpt-4o".into()),
        origin: Some(strip_query_and_fragment(
            "https://api.openai.com/v1?sig=secret",
        )),
        capability_source: "configured".into(),
        capability_freshness: "fresh".into(),
        config_generation: 1,
        mode,
        available: true,
        fallback_outcome: None,
        reason: "selected".into(),
    }
}

fn sample_grant(scope: GrantScope) -> GrantView {
    GrantView {
        grant_id: "grant-1".into(),
        version: 1,
        project: "project".into(),
        destination: "https://api.openai.com".into(),
        media_class: "image".into(),
        purpose: "ask_image".into(),
        scope,
        session_binding: (scope == GrantScope::Session).then(|| "session".into()),
        invocation_binding: (scope == GrantScope::Once).then(|| "inv-1".into()),
        created_at: "1".into(),
        last_used_at: None,
        revoked: false,
        consumed: false,
    }
}

fn sample_invocation() -> InvocationView {
    InvocationView {
        invocation_id: "inv-1".into(),
        parent_operation: "ask_image".into(),
        session: "session".into(),
        purpose_label: "ask_image".into(),
        provider: "openai".into(),
        model: "gpt-4o".into(),
        location: "public_cloud".into(),
        state: InvocationState::Completed,
        created_at: "1".into(),
        dispatched_at: Some("2".into()),
        terminal_at: Some("3".into()),
        grant_id: Some("grant-1".into()),
        disposition: InvocationDisposition::Granted,
        usage_input_tokens: Some(10),
        usage_output_tokens: Some(4),
        usage_cost_micro_usd: Some(12),
        sidecar_invocation_charged: true,
        media_reservation_id: Some("res-1".into()),
        provider_concurrency_slot: Some("slot-1".into()),
        safe_error: None,
        owner_detail: Some(OwnerTechnicalDetail {
            purpose: "ask_image".into(),
            instruction_version: 1,
            body_digest_hex: "ab".repeat(32),
            unicode_scalar_len: 12,
            utf8_byte_len: 12,
        }),
    }
}

fn authority_snapshot(
    daemon_instance_id: &str,
    project_id: &str,
    session_id: &str,
    selection_id: &str,
    config_generation: u64,
    cap: u64,
    source: cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1,
    approval_mode: cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1,
) -> cockpit_proto::image_sidecar_authority::ImageSidecarAuthoritySnapshotV1 {
    cockpit_proto::image_sidecar_authority::ImageSidecarAuthoritySnapshotV1 {
        schema_version: 1,
        daemon_instance_id: daemon_instance_id.into(),
        session_id: session_id.into(),
        project_id: project_id.into(),
        config_generation,
        selection_id: selection_id.into(),
        entity_version: 1,
        approval_mode,
        central_invocation_cap: cap,
        central_invocation_cap_source: source,
        central_invocation_cap_hard_ceiling: 128,
        pipeline_available: false,
        health_reason: PIPELINE_UNAVAILABLE_REASON.into(),
        models: Vec::new(),
        resolution: cockpit_proto::image_sidecar_authority::ImageSidecarResolutionV1 {
            provider: None,
            model: None,
            origin: None,
            available: false,
            reason: PIPELINE_UNAVAILABLE_REASON.into(),
            grant_candidate_id: None,
            primary: None,
            matched_source: "missing_selection".into(),
            capability_source: "none".into(),
            capability_freshness: "unavailable".into(),
            mode: "automatic".into(),
            fallback_outcome: None,
        },
        grants: Vec::new(),
        invocations: Vec::new(),
    }
}

fn grant_mutation(
    entity_version: u64,
) -> cockpit_proto::image_sidecar_authority::ImageSidecarGrantMutationV1 {
    cockpit_proto::image_sidecar_authority::ImageSidecarGrantMutationV1 {
        schema_version: 1,
        daemon_instance_id: "local".into(),
        session_id: "session".into(),
        config_generation: 1,
        selection_id: "selection".into(),
        entity_version,
        grant: cockpit_proto::image_sidecar_authority::ImageSidecarGrantV1 {
            grant_id: "grant-1".into(),
            version: 1,
            project_id: "project".into(),
            destination: "https://api.openai.com".into(),
            purpose: "ask_image".into(),
            scope: cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Project,
            session_id: None,
            invocation_id: None,
            created_at_unix_ms: 1,
            last_used_at_unix_ms: None,
            revoked_at_unix_ms: None,
            consumed_at_unix_ms: None,
        },
    }
}

fn unbound_overview_page() -> SidecarPage {
    SidecarPage {
        kind: SidecarPageKind::Overview,
        session: SidecarSession::with_authoritative_config(
            SidecarPrincipal::local_owner(),
            &SidecarSelectionConfig::default(),
            4,
            true,
            "project".into(),
            "selection".into(),
            1,
        ),
    }
}

fn page_with(kind: SidecarPageKind) -> SidecarPage {
    let mut session = SidecarSession::new(SidecarPrincipal::local_owner());
    session.reducer = SidecarReducer::new(
        "local".into(),
        "project".into(),
        "session".into(),
        "selection".into(),
        1,
    );
    session.authoritative_mutations = true;
    session.authoritative_snapshot = true;
    session.form.models = vec![
        SidecarModelOption {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            configured: true,
            image_capable: true,
            fresh: true,
        },
        SidecarModelOption {
            provider: "openai".into(),
            model: "gpt-text".into(),
            configured: true,
            image_capable: false,
            fresh: true,
        },
        SidecarModelOption {
            provider: "openai".into(),
            model: "stale-vision".into(),
            configured: true,
            image_capable: true,
            fresh: false,
        },
        SidecarModelOption {
            provider: "discovered-only".into(),
            model: "fresh-vision".into(),
            configured: false,
            image_capable: true,
            fresh: true,
        },
    ];
    session.reducer.resolution = Some(sample_trace(SidecarModeChoice::Automatic));
    session.reducer.grant_candidate_id = Some("daemon-candidate".into());
    session.reducer.health = Some(HealthView {
        available: true,
        capability_source: "configured".into(),
        freshness: "fresh".into(),
        reason: "ok".into(),
    });
    SidecarPage { kind, session }
}

#[test]
fn cap_only_save_preserves_configured_models_when_catalog_is_unavailable() {
    let config = SidecarSelectionConfig {
        mode: cockpit_core::image_sidecar::SidecarMode::Always,
        trusted_primary_default: Some(SidecarProviderModel {
            provider: "configured".into(),
            model: "vision".into(),
        }),
        untrusted_primary_default: Some(SidecarProviderModel {
            provider: "configured".into(),
            model: "vision-untrusted".into(),
        }),
        per_primary_override: Some(SidecarProviderModel {
            provider: "configured".into(),
            model: "override".into(),
        }),
    };
    let mut form = SidecarFormState::from_authoritative_config(&config);
    form.set_central_cap(7);
    assert_eq!(form.to_selection_config(), config);
}

#[test]
fn sidecar_save_preserves_existing_discovered_selection_without_offering_it_again() {
    let retained = SidecarModelRef {
        provider: "catalog-only".into(),
        model: "vision".into(),
    };
    let mut form = SidecarFormState {
        trusted_default: Some(retained.clone()),
        models: vec![SidecarModelOption {
            provider: "configured".into(),
            model: "vision".into(),
            configured: true,
            image_capable: true,
            fresh: true,
        }],
        ..SidecarFormState::default()
    };
    form.set_central_cap(7);
    assert!(
        form.selectable_models()
            .iter()
            .all(|model| model.provider != retained.provider)
    );
    assert_eq!(
        form.to_selection_config()
            .trusted_primary_default
            .expect("retained selection"),
        SidecarProviderModel {
            provider: retained.provider,
            model: retained.model,
        }
    );
}

#[test]
fn sidecar_editors_expose_a_named_dirty_save_control() {
    let mut page = page_with(SidecarPageKind::ModeEditor);
    let save = page
        .named_actions()
        .into_iter()
        .find(|(action, _, _)| matches!(action, SidecarAction::SaveSelection))
        .expect("mode editor must expose Save changes");
    assert!(!save.1);
    assert_eq!(save.2, Some(REASON_NO_PENDING_CHANGES));
    page.session.form.local_edits_preserved = true;
    assert!(
        page.named_actions()
            .into_iter()
            .any(|(action, enabled, reason)| {
                matches!(action, SidecarAction::SaveSelection) && enabled && reason.is_none()
            })
    );
}

#[test]
fn sidecar_releases_only_the_matching_rejected_config_save() {
    let mut session = SidecarSession::new(SidecarPrincipal::local_owner());
    session.save_pending = true;
    session.save_operation_id = Some("save-a".into());
    session.save_base_revision = Some("safe-revision".into());
    session.busy = true;
    assert!(!session.complete_config_rejection("save-b", "conflict"));
    assert!(session.save_pending);
    assert!(session.busy);
    assert!(session.complete_config_rejection("save-a", "conflict"));
    assert!(!session.save_pending);
    assert!(!session.busy);
    assert_eq!(session.conflict.as_deref(), Some("conflict"));
    assert!(session.save_base_revision.is_none());
    assert_eq!(
        session.reload_required_base_revision.as_deref(),
        Some("safe-revision")
    );
    assert!(session.requires_reload_before_reapply());
    session.reconcile_reloaded_revision(Some("safe-revision"));
    assert!(session.requires_reload_before_reapply());
    session.reconcile_reloaded_revision(Some("current-revision"));
    assert!(!session.requires_reload_before_reapply());
    assert!(session.conflict.is_none());

    let mut page = page_with(SidecarPageKind::ModeEditor);
    page.session.form.local_edits_preserved = true;
    page.session.reload_required_before_reapply = true;
    let save = page
        .named_actions()
        .into_iter()
        .find(|(action, _, _)| matches!(action, SidecarAction::SaveSelection))
        .expect("mode editor exposes Save changes");
    assert!(!save.1);
    assert_eq!(save.2, Some(REASON_RELOAD_REQUIRED));
}

#[test]
fn sidecar_commits_only_the_matching_config_save() {
    let mut session = SidecarSession::new(SidecarPrincipal::local_owner());
    session.save_pending = true;
    session.save_operation_id = Some("save-a".into());
    session.save_base_revision = Some("safe-revision".into());
    session.busy = true;
    session.form.central_cap = 7;
    assert!(!session.complete_config_save("save-b", Some(2)));
    assert!(session.save_pending);
    assert!(session.busy);
    assert!(session.complete_config_save("save-a", Some(2)));
    assert!(!session.save_pending);
    assert!(!session.busy);
    assert_eq!(session.policy.value, 7);
    assert!(session.reducer.stale);

    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::ModeEditor);
    page.session.save_pending = true;
    page.session.save_operation_id = Some("save-a".into());
    page.session.save_base_revision = Some("old-revision".into());
    page.session.busy = true;
    dialog.cx.extended_revision = Some("new-revision".into());
    page.apply_authoritative_settings_completion(&mut dialog.cx, None);
    assert!(
        page.session.save_pending,
        "a sibling revision change must not complete an unbound sidecar save"
    );
    dialog.cx.mark_extended_save_committed_for_test("save-a");
    page.apply_authoritative_settings_completion(&mut dialog.cx, None);
    assert!(!page.session.save_pending);
}

#[test]
fn sidecar_snapshot_rehydrates_generation_policy_and_yolo_after_identity_rebind() {
    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::Overview);
    page.session.reducer.config_generation = 3;
    let initial = authority_snapshot(
        "local",
        "project",
        "session",
        "selection",
        3,
        19,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Profile,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Yolo,
    );
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            initial,
        ))),
    );
    assert_eq!(page.session.reducer.config_generation, 3);
    assert_eq!(page.session.policy.value, 19);
    assert_eq!(
        page.session.policy.source,
        SidecarInvocationCapProvenance::Profile
    );
    assert_eq!(page.session.approval_mode, ApprovalMode::Yolo);
    assert!(!page.session.first_use().prompt);
    assert_eq!(
        page.session.first_use().yolo_label,
        Some("agent_discretion")
    );

    let rebound = authority_snapshot(
        "new-daemon",
        "new-project",
        "new-session",
        "new-selection",
        7,
        11,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Adapter,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask,
    );
    page.session.save_pending = true;
    page.session.save_operation_id = Some("save-old-identity".into());
    page.session.busy = true;
    page.session.form.mode = SidecarModeChoice::Never;
    page.session.form.local_edits_preserved = true;
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            rebound,
        ))),
    );
    assert_eq!(page.session.reducer.config_generation, 7);
    assert_eq!(page.session.policy.value, 11);
    assert_eq!(
        page.session.policy.source,
        SidecarInvocationCapProvenance::Adapter
    );
    assert_eq!(page.session.approval_mode, ApprovalMode::Ask);
    assert!(page.session.first_use().prompt);
    assert!(!page.session.reducer.stale);
    assert!(!page.session.save_pending);
    assert!(page.session.save_operation_id.is_none());
    assert!(!page.session.busy);
    assert_eq!(page.session.form.mode, SidecarModeChoice::Automatic);
    assert!(!page.session.form.local_edits_preserved);
}

#[test]
fn sidecar_first_authority_snapshot_binds_identity_without_dropping_cas_or_edits() {
    let mut dialog = test_dialog();
    let mut page = unbound_overview_page();
    assert!(page.session.reducer.daemon_instance.is_empty());
    assert!(page.session.reducer.session_id.is_empty());
    page.session.form.mode = SidecarModeChoice::Never;
    page.session.form.central_cap = 9;
    page.session.form.local_edits_preserved = true;
    page.session.save_pending = true;
    page.session.save_operation_id = Some("save-open".into());
    page.session.busy = true;
    let snapshot = authority_snapshot(
        "local",
        "project",
        "session",
        "selection",
        1,
        4,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Configured,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask,
    );
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            snapshot,
        ))),
    );
    assert_eq!(page.session.reducer.daemon_instance, "local");
    assert_eq!(page.session.reducer.session_id, "session");
    assert_eq!(page.session.reducer.project_id, "project");
    assert_eq!(page.session.reducer.selection_id, "selection");
    assert_eq!(page.session.form.mode, SidecarModeChoice::Never);
    assert_eq!(page.session.form.central_cap, 9);
    assert!(page.session.form.local_edits_preserved);
    assert!(page.session.save_pending);
    assert_eq!(page.session.save_operation_id.as_deref(), Some("save-open"));
    assert!(page.session.busy);
    assert_eq!(page.session.reducer.config_generation, 1);
    assert!(!page.session.reducer.stale);
}

#[test]
fn sidecar_opening_snapshot_does_not_rewind_generation_after_save() {
    let mut dialog = test_dialog();
    let mut page = unbound_overview_page();
    page.session.save_pending = true;
    page.session.save_operation_id = Some("save-a".into());
    page.session.busy = true;
    page.session.form.central_cap = 7;
    assert!(page.session.complete_config_save("save-a", Some(2)));
    assert_eq!(page.session.reducer.config_generation, 2);
    let snapshot = authority_snapshot(
        "local",
        "project",
        "session",
        "selection",
        1,
        4,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Configured,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask,
    );
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            snapshot,
        ))),
    );
    assert_eq!(page.session.reducer.config_generation, 2);
    assert_eq!(page.session.reducer.daemon_instance, "local");
    assert_eq!(page.session.reducer.session_id, "session");
    assert!(page.session.reducer.stale);
    assert!(!page.session.authoritative_mutations);
    assert!(!page.session.save_pending);
}

#[test]
fn sidecar_sibling_authority_completion_keeps_busy_while_save_pending() {
    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::GrantList);
    page.session.save_pending = true;
    page.session.save_operation_id = Some("save-a".into());
    page.session.busy = true;

    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::Ack)),
    );
    assert!(page.session.busy);
    assert!(page.session.save_pending);
    assert_eq!(page.session.save_operation_id.as_deref(), Some("save-a"));

    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Err("authority unavailable".into())),
    );
    assert!(page.session.busy);
    assert!(page.session.save_pending);
    assert_eq!(page.session.save_operation_id.as_deref(), Some("save-a"));

    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarGrantMutated(
            grant_mutation(1),
        ))),
    );
    assert!(page.session.busy);
    assert!(page.session.save_pending);
    assert_eq!(page.session.save_operation_id.as_deref(), Some("save-a"));
    assert_eq!(page.session.reducer.grants.len(), 1);

    page.session.save_pending = false;
    page.session.save_operation_id = None;
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::Ack)),
    );
    assert!(!page.session.busy);
}

#[test]
fn sidecar_authority_rpc_occupancy_keeps_busy_without_save_pending() {
    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::GrantList);
    assert!(!page.session.save_pending);
    page.session.begin_authority_rpc();
    page.session.begin_authority_rpc();
    assert!(page.session.busy);

    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Err("authority unavailable".into())),
    );
    assert!(
        page.session.busy,
        "a sibling authority completion must not drop occupancy of another in-flight RPC"
    );
    assert!(!page.session.save_pending);

    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::Ack)),
    );
    assert!(!page.session.busy);
}

#[test]
fn sidecar_late_mismatch_and_discarded_completions_settle_authority_busy() {
    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::Overview);
    let current = authority_snapshot(
        "local",
        "project",
        "session",
        "selection",
        1,
        8,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Configured,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask,
    );
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            current.clone(),
        ))),
    );
    assert_eq!(page.session.reducer.entity_version, 1);

    page.session.begin_authority_rpc();
    assert!(page.session.busy);
    let mut late = current.clone();
    late.entity_version = 0;
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            late,
        ))),
    );
    assert!(
        !page.session.busy,
        "Late is still the settler of the RPC that produced the snapshot"
    );

    page.session.begin_authority_rpc();
    assert!(page.session.busy);
    let mut mismatched = current;
    mismatched.selection_id = "other-selection".into();
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            mismatched,
        ))),
    );
    assert!(
        !page.session.busy,
        "identity/schema mismatch must settle occupancy of the completed RPC"
    );

    page.session.reducer.stale = false;
    page.session.reducer.entity_version = 1;
    page.session.error = None;
    page.session.begin_authority_rpc();
    assert!(page.session.busy);
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarGrantMutated(
            grant_mutation(1),
        ))),
    );
    assert!(
        !page.session.busy,
        "Discarded grant envelopes must still settle the RPC occupancy they complete"
    );
}

#[test]
fn sidecar_complete_config_save_keeps_busy_while_authority_rpc_in_flight() {
    let mut session = SidecarSession::new(SidecarPrincipal::local_owner());
    session.save_pending = true;
    session.save_operation_id = Some("save-a".into());
    session.begin_authority_rpc();
    assert!(session.busy);
    assert!(session.complete_config_save("save-a", Some(2)));
    assert!(!session.save_pending);
    assert!(
        session.busy,
        "dropping the CAS bit must not clear occupancy of an in-flight authority RPC"
    );
}

#[test]
fn sidecar_post_save_rehydrate_stays_busy_on_sibling_error() {
    let mut dialog = test_dialog();
    dialog.cx.extended_base["__cockpit_settings_generation"] = serde_json::json!(2);
    let mut page = page_with(SidecarPageKind::ModeEditor);
    page.session.save_pending = true;
    page.session.save_operation_id = Some("save-a".into());
    page.session.begin_authority_rpc();
    page.session.sync_authority_busy();
    dialog.cx.mark_extended_save_committed_for_test("save-a");
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Err("generation moved".into())),
    );
    assert!(!page.session.save_pending);
    assert!(
        page.session.busy,
        "opening-GET error must not drop the post-save rehydrate fence"
    );
    assert!(dialog.cx.sidecar_authority_pending());
}

#[test]
fn sidecar_gap_follow_up_failure_releases_authority_busy() {
    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::Overview);
    page.session.reducer.entity_version = 1;
    page.session.reducer.config_generation = 0;
    page.session.begin_authority_rpc();
    assert!(page.session.busy);
    let mut gap = authority_snapshot(
        "local",
        "project",
        "session",
        "selection",
        0,
        8,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Configured,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask,
    );
    gap.entity_version = 9;
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            gap,
        ))),
    );
    assert!(page.session.reducer.stale);
    assert!(
        !page.session.busy,
        "a Gap follow-up that cannot queue must not pin busy with no owner"
    );
    assert!(!dialog.cx.sidecar_authority_pending());
}

#[test]
fn sidecar_opening_snapshot_queue_occupies_busy() {
    let queued = sidecar_overview_page_from_snapshot(
        SidecarPrincipal::local_owner(),
        &SidecarSelectionConfig::default(),
        4,
        true,
        "project".into(),
        "selection".into(),
        1,
        true,
    );
    let queued = queued
        .as_any()
        .downcast_ref::<SidecarPage>()
        .expect("sidecar overview page");
    assert!(queued.session.busy);
    assert!(!queued.session.save_pending);

    let idle = sidecar_overview_page_from_snapshot(
        SidecarPrincipal::local_owner(),
        &SidecarSelectionConfig::default(),
        4,
        true,
        "project".into(),
        "selection".into(),
        1,
        false,
    );
    let idle = idle
        .as_any()
        .downcast_ref::<SidecarPage>()
        .expect("sidecar overview page");
    assert!(!idle.session.busy);
}

#[test]
fn sidecar_unavailable_primary_trace_is_not_rendered_as_untrusted() {
    let dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::ResolverDetail);
    page.session.reducer.resolution.as_mut().unwrap().primary = None;
    let rendered = render_page_lines(&page, &dialog, 100, 30).join("\n");
    assert!(rendered.contains("Primary resolver details unavailable."));
    assert!(!rendered.contains("Trust class: untrusted"));
    assert!(!rendered.contains("primary=: trust="));
}

#[test]
fn sidecar_snapshot_applies_resolver_projection_not_a_client_invented_trace() {
    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::ResolverDetail);
    let mut snapshot = authority_snapshot(
        "local",
        "project",
        "session",
        "selection",
        1,
        8,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Configured,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask,
    );
    snapshot.resolution = cockpit_proto::image_sidecar_authority::ImageSidecarResolutionV1 {
        provider: None,
        model: None,
        origin: None,
        available: false,
        reason: "never_mode".into(),
        grant_candidate_id: None,
        primary: Some(
            cockpit_proto::image_sidecar_authority::ImageSidecarPrimaryV1 {
                provider: "openai".into(),
                model: "gpt-4o".into(),
                trust: "untrusted".into(),
                location: "public_cloud".into(),
                credential_fingerprint: "abcd".repeat(16),
            },
        ),
        matched_source: "never_mode".into(),
        capability_source: "none".into(),
        capability_freshness: "unavailable".into(),
        mode: "never".into(),
        fallback_outcome: None,
    };
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            snapshot,
        ))),
    );
    let trace = page
        .session
        .reducer
        .resolution
        .as_ref()
        .expect("resolver projection");
    assert_eq!(trace.matched_source, "never_mode");
    assert_eq!(trace.reason, "never_mode");
    assert_eq!(trace.mode, SidecarModeChoice::Never);
    assert_eq!(
        trace.primary.as_ref().map(|primary| primary.trust.as_str()),
        Some("untrusted")
    );
    assert!(trace.sidecar_provider.is_none());
    assert_eq!(trace.capability_freshness, "unavailable");
    let rendered = render_page_lines(&page, &dialog, 100, 30).join("\n");
    assert!(rendered.contains("primary=openai:gpt-4o trust=untrusted"));
    assert!(rendered.contains("matched=never_mode"));
    assert!(!rendered.contains("matched=daemon"));
}

#[test]
fn sidecar_grant_mutation_gap_invalidates_and_rehydrates_without_applying_it() {
    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::GrantList);
    page.session.reducer.entity_version = 1;
    page.session.reducer.grants = vec![sample_grant(GrantScope::Project)];
    let mutation = cockpit_proto::image_sidecar_authority::ImageSidecarGrantMutationV1 {
        schema_version: 1,
        daemon_instance_id: "local".into(),
        session_id: "session".into(),
        config_generation: 1,
        selection_id: "selection".into(),
        entity_version: 3,
        grant: cockpit_proto::image_sidecar_authority::ImageSidecarGrantV1 {
            grant_id: "gap-grant".into(),
            version: 1,
            project_id: "project".into(),
            destination: "https://api.openai.com".into(),
            purpose: "ask_image".into(),
            scope: cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Project,
            session_id: None,
            invocation_id: None,
            created_at_unix_ms: 1,
            last_used_at_unix_ms: None,
            revoked_at_unix_ms: None,
            consumed_at_unix_ms: None,
        },
    };
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarGrantMutated(
            mutation,
        ))),
    );
    assert!(page.session.reducer.stale);
    assert_eq!(page.session.reducer.entity_version, 1);
    assert!(page.session.reducer.grants.is_empty());
    assert!(!page.session.authoritative_mutations);
}

#[test]
fn image_sidecar_settings_resolver_form_matrix() {
    let mut form = SidecarFormState::default();
    form.models = vec![
        SidecarModelOption {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            configured: true,
            image_capable: true,
            fresh: true,
        },
        SidecarModelOption {
            provider: "openai".into(),
            model: "gpt-text".into(),
            configured: true,
            image_capable: false,
            fresh: true,
        },
        SidecarModelOption {
            provider: "openai".into(),
            model: "stale-vision".into(),
            configured: true,
            image_capable: true,
            fresh: false,
        },
    ];
    let selectable = form.selectable_models();
    assert_eq!(selectable.len(), 1);
    assert_eq!(selectable[0].model, "gpt-4o");
    assert!(selectable.iter().all(|model| model.configured));

    let mut page = page_with(SidecarPageKind::DefaultEditor);
    page.session.form = form.clone();
    page.handle_pointer_control(
        &mut test_dialog(),
        SettingsPointerAction::Sidecar(SidecarAction::SetTrustedDefault(SidecarModelRef {
            provider: "discovered-only".into(),
            model: "fresh-vision".into(),
        })),
    );
    assert!(
        page.session
            .form
            .to_selection_config()
            .trusted_primary_default
            .is_none(),
        "a discovered but unconfigured model must not enter a mutation request"
    );
    assert_eq!(
        page.session.remediation,
        Some(SidecarRemediation::MissingSelection)
    );

    for mode in [
        SidecarModeChoice::Automatic,
        SidecarModeChoice::Always,
        SidecarModeChoice::Never,
    ] {
        form.mode = mode;
        let pair = SidecarModelRef {
            provider: "openai".into(),
            model: "gpt-4o".into(),
        };
        form.trusted_default = Some(pair.clone());
        form.untrusted_default = Some(pair.clone());
        form.override_pair = Some(pair);
        let config = form.to_selection_config();
        assert_eq!(config.mode, mode.to_core());
        let json = serde_json::to_value(&config).unwrap();
        assert!(
            json.get("sidecar_invocations_per_session").is_none(),
            "selection config must not serialize a sidecar-local cap: {json}"
        );
        assert!(json.get("invocation_cap").is_none());
        let encoded = serde_json::to_string(&config).unwrap();
        assert!(!encoded.contains("sidecar_invocations_per_session"));
    }

    form.set_central_cap(32);
    assert_eq!(form.central_cap, 32);
    form.set_central_cap(10_000);
    assert_eq!(
        form.central_cap,
        MediaResourceLimits::hard_ceilings().sidecar_invocations_per_session
    );

    let mut page = page_with(SidecarPageKind::CentralPolicyEditor);
    page.session.form = form.clone();
    page.session.policy = CentralPolicyView {
        value: 32,
        source: SidecarInvocationCapProvenance::Configured,
        hard_ceiling: MediaResourceLimits::hard_ceilings().sidecar_invocations_per_session,
    };
    let dialog = test_dialog();
    let lines = render_page_lines(&page, &dialog, 100, 30);
    let joined = lines.join("\n");
    assert!(joined.contains("Effective: 32 source=configured hard_ceiling=128"));
    assert!(joined.contains("Draft sidecar_invocations_per_session="));
    assert!(joined.contains("No sidecar-local cap is stored."));

    let mut resolver = page_with(SidecarPageKind::ResolverDetail);
    resolver.session.reducer.resolution = Some(sample_trace(SidecarModeChoice::Always));
    resolver.session.policy = CentralPolicyView {
        value: 32,
        source: SidecarInvocationCapProvenance::Configured,
        hard_ceiling: 128,
    };
    let lines = render_page_lines(&resolver, &dialog, 100, 30);
    let joined = lines.join("\n");
    assert!(joined.contains("primary=openai:gpt-4o trust=trusted"));
    assert!(joined.contains("matched=trust_class_default"));
    assert!(joined.contains("origin=https://api.openai.com/v1"));
    assert!(!joined.contains("sig=secret"));
    assert!(joined.contains("credential_fingerprint="));
    assert!(joined.contains("config_generation=1 mode=always"));
    assert!(joined.contains("Effective: 32 source=configured hard_ceiling=128"));
}

#[test]
fn image_sidecar_settings_grant_scope_and_revoke() {
    let scopes = offered_grant_scopes();
    assert_eq!(
        scopes,
        [GrantScope::Once, GrantScope::Session, GrantScope::Project]
    );
    let mut page = page_with(SidecarPageKind::GrantEditor);
    page.session.approval_mode = ApprovalMode::Ask;
    let dialog = test_dialog();
    let lines = render_page_lines(&page, &dialog, 100, 30);
    let joined = lines.join("\n").to_lowercase();
    assert!(joined.contains("[once]"));
    assert!(joined.contains("[session]"));
    assert!(joined.contains("[project]"));
    assert!(!joined.contains("global"));
    assert!(!joined.contains("wildcard"));
    for row in &lines {
        assert!(
            !row.to_lowercase().contains("max") && !row.to_lowercase().contains("ceiling"),
            "grant editor must not show maxima: {row}"
        );
    }

    let mut list = page_with(SidecarPageKind::GrantList);
    list.session.reducer.grants = vec![sample_grant(GrantScope::Project)];
    let lines = render_page_lines(&list, &dialog, 100, 30);
    let joined = lines.join("\n");
    assert!(joined.contains(PROJECT_GRANT_WARNING));
    assert!(joined.contains("project=project"));
    assert!(joined.contains("dest=https://api.openai.com"));
    assert!(joined.contains("media=image"));
    assert!(joined.contains("purpose=ask_image"));
    assert!(joined.contains("scope=project"));
    assert!(joined.contains("Effective:"));
    assert!(joined.contains("hard_ceiling="));
    assert!(!joined.to_lowercase().contains("global"));

    let mut dialog = test_dialog();
    list.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    assert!(list.session.confirm_revoke.borrow().is_some());
    let lines = render_page_lines(&list, &dialog, 100, 30);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Revoke grant? [Revoke grant] [Cancel]"))
    );

    list.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::ConfirmRevokeGrant(
            SidecarGrantId("stale".into()),
            ConfirmationChoice::Confirm,
        )),
    );
    assert!(!list.session.reducer.grants[0].revoked);
    assert!(list.session.confirm_revoke.borrow().is_none());
    assert_eq!(
        list.session.error.as_deref(),
        Some(REASON_REVOKE_CONFIRMATION_STALE)
    );

    *list.session.confirm_revoke.borrow_mut() = Some(PendingRevoke {
        grant_id: "grant-1".into(),
        version: 1,
        layout: None,
    });
    list.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::ConfirmRevokeGrant(
            SidecarGrantId("grant-1".into()),
            ConfirmationChoice::Confirm,
        )),
    );
    assert!(!list.session.reducer.grants[0].revoked);
    let effect = dialog
        .take_daemon_effect()
        .expect("authoritative revoke request");
    assert!(matches!(
        effect.work,
        SettingsDaemonEffectWork::Request(cockpit_proto::Request::RevokeImageSidecarGrant {
            grant_id,
            expected_version: 1,
            ..
        }) if grant_id == "grant-1"
    ));
    assert!(list.session.confirm_revoke.borrow().is_none());
}

#[test]
fn image_sidecar_revoke_confirmation_rechecks_current_authorization_and_grant_identity() {
    let mut page = page_with(SidecarPageKind::GrantList);
    page.session.reducer.grants = vec![sample_grant(GrantScope::Once)];
    let mut dialog = test_dialog();

    page.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    page.session.principal = SidecarPrincipal::default();
    page.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::ConfirmRevokeGrant(
            SidecarGrantId("grant-1".into()),
            ConfirmationChoice::Confirm,
        )),
    );
    assert!(!page.session.reducer.grants[0].revoked);
    assert!(page.session.confirm_revoke.borrow().is_none());
    assert_eq!(
        page.session.error.as_deref(),
        Some(REASON_REVOKE_REQUIRES_AUTHORIZATION)
    );

    page.session.principal = SidecarPrincipal::local_owner();
    page.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    page.session.reducer.grants[0].version = 2;
    page.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::ConfirmRevokeGrant(
            SidecarGrantId("grant-1".into()),
            ConfirmationChoice::Confirm,
        )),
    );
    assert!(!page.session.reducer.grants[0].revoked);
    assert!(page.session.confirm_revoke.borrow().is_none());
    assert_eq!(
        page.session.error.as_deref(),
        Some(REASON_REVOKE_CONFIRMATION_STALE)
    );
}

#[test]
fn image_sidecar_revoke_confirmation_cancels_when_layout_changes_or_blocks() {
    let mut page = page_with(SidecarPageKind::GrantList);
    page.session.reducer.grants = vec![sample_grant(GrantScope::Once)];
    let dialog = test_dialog();

    let _ = render_page_lines(&page, &dialog, 100, 30);
    page.handle_pointer_control(
        &mut test_dialog(),
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    assert!(page.session.confirm_revoke.borrow().is_some());
    let _ = render_page_lines(&page, &dialog, 80, 24);
    assert!(page.session.confirm_revoke.borrow().is_none());
    assert!(!page.session.reducer.grants[0].revoked);

    page.handle_pointer_control(
        &mut test_dialog(),
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    assert!(page.session.confirm_revoke.borrow().is_some());
    let _ = render_page_lines(&page, &dialog, 40, 10);
    assert!(page.session.confirm_revoke.borrow().is_none());
    assert!(!page.session.reducer.grants[0].revoked);
}

#[test]
fn image_sidecar_settings_ask_yolo_first_use() {
    let ask = FirstUseView::for_mode(ApprovalMode::Ask);
    assert_eq!(
        ask.grant_choices,
        vec![GrantScope::Once, GrantScope::Session, GrantScope::Project]
    );
    assert!(ask.prompt);
    assert!(!ask.standing_grant);
    assert!(ask.yolo_label.is_none());

    let yolo = FirstUseView::for_mode(ApprovalMode::Yolo);
    assert!(yolo.grant_choices.is_empty());
    assert!(!yolo.prompt);
    assert!(!yolo.standing_grant);
    assert_eq!(yolo.yolo_label, Some("agent_discretion"));

    let dialog = test_dialog();
    let mut ask_page = page_with(SidecarPageKind::GrantEditor);
    ask_page.session.approval_mode = ApprovalMode::Ask;
    let joined = render_page_lines(&ask_page, &dialog, 100, 30).join("\n");
    assert!(joined.contains("[once]"));
    assert!(joined.contains("First use"));

    let mut yolo_page = page_with(SidecarPageKind::GrantList);
    yolo_page.session.approval_mode = ApprovalMode::Yolo;
    let joined = render_page_lines(&yolo_page, &dialog, 100, 30).join("\n");
    assert!(joined.contains("agent_discretion"));
    assert!(joined.contains("No standing grant"));
    assert!(!joined.contains("First use"));
    assert!(!joined.to_lowercase().contains("[once]"));
}

#[test]
fn image_sidecar_settings_trust_vs_egress_disclosure() {
    let trusted = TrustDisclosure::for_trust(true);
    let untrusted = TrustDisclosure::for_trust(false);
    assert_eq!(trusted.trust_class, "trusted");
    assert_eq!(untrusted.trust_class, "untrusted");
    let trusted_auth = EgressAuthorityView::shared("https://api.openai.com");
    let untrusted_auth = EgressAuthorityView::shared("https://api.openai.com");
    assert_eq!(trusted_auth, untrusted_auth);
    assert_eq!(trusted_auth.scopes, offered_grant_scopes());
    for disclosure in [&trusted, &untrusted] {
        let text = disclosure.lines().join(" ");
        assert!(text.contains("Trust does not grant egress"));
        assert!(!text.to_lowercase().contains("consent"));
        assert!(!text.to_lowercase().contains("trusted therefore"));
        assert!(!text.to_lowercase().contains("implies"));
    }
    assert_ne!(trusted.redaction, untrusted.redaction);

    let dialog = test_dialog();
    let page = page_with(SidecarPageKind::ResolverDetail);
    let joined = render_page_lines(&page, &dialog, 100, 30)
        .join("\n")
        .to_lowercase();
    assert!(!joined.contains("consent"));
}

#[test]
fn image_sidecar_settings_invocation_accounting_redaction() {
    let mut page = page_with(SidecarPageKind::InvocationDetail);
    page.session.reducer.invocations = vec![sample_invocation()];
    page.session.selected_invocation = Some("inv-1".into());
    let dialog = test_dialog();
    let joined = render_page_lines(&page, &dialog, 100, 40).join("\n");
    assert!(joined.contains("purpose=ask_image"));
    assert!(joined.contains("parent=ask_image"));
    assert!(joined.contains("session=session"));
    assert!(joined.contains("openai:gpt-4o"));
    assert!(joined.contains("state=completed"));
    assert!(joined.contains("disposition=granted"));
    assert!(joined.contains("charged=true"));
    assert!(joined.contains("owner purpose=ask_image version=1 digest="));
    for forbidden in [
        "pixels",
        "prompt",
        "question text",
        "preview",
        "transcript",
        "authorization: Bearer",
        "api_key",
        "signed",
        "?sig=",
        "raw payload",
        "attachment metadata",
    ] {
        assert!(
            !joined.to_lowercase().contains(&forbidden.to_lowercase()),
            "invocation view leaked {forbidden}: {joined}"
        );
    }
}

#[test]
fn image_sidecar_settings_stale_invocation_action_is_inert() {
    let mut page = page_with(SidecarPageKind::InvocationList);
    page.session.reducer.invocations = vec![sample_invocation()];
    let nav = page.handle_pointer_control(
        &mut test_dialog(),
        SettingsPointerAction::Sidecar(SidecarAction::OpenInvocationDetail(SidecarInvocationId(
            "deleted-invocation".into(),
        ))),
    );
    assert!(matches!(nav, Nav::Stay));
    assert!(page.session.selected_invocation.is_none());
    assert_eq!(
        page.session.error.as_deref(),
        Some(REASON_INVOCATION_NOT_FOUND)
    );

    page.kind = SidecarPageKind::InvocationDetail;
    let rendered = build_rows(&page)
        .into_iter()
        .map(|(text, _)| text)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(rendered.contains("Invocation not found."));
    assert!(!rendered.contains("inv-1 |"));
}

#[test]
fn image_sidecar_settings_reducer_rejects_stale_events() {
    let mut reducer = SidecarReducer::new("d1".into(), "p1".into(), "s1".into(), "sel1".into(), 1);
    let inv = sample_invocation();
    let mk = |version: u64, payload: SidecarEventPayload| SidecarEvent {
        daemon_instance: "d1".into(),
        project_id: "p1".into(),
        session_id: "s1".into(),
        selection_id: "sel1".into(),
        config_generation: 1,
        entity_version: version,
        payload,
    };
    assert_eq!(
        reducer.apply(mk(1, SidecarEventPayload::Invocation(inv.clone()))),
        SidecarEventOutcome::Applied
    );
    assert_eq!(reducer.charged_count, 1);
    assert_eq!(
        reducer.apply(mk(1, SidecarEventPayload::Invocation(inv.clone()))),
        SidecarEventOutcome::Discarded
    );
    assert_eq!(reducer.charged_count, 1);
    let mut late = inv.clone();
    late.state = InvocationState::Pending;
    assert_eq!(
        reducer.apply(mk(2, SidecarEventPayload::Invocation(late))),
        SidecarEventOutcome::Discarded
    );
    assert_eq!(reducer.invocations[0].state, InvocationState::Completed);

    let mut wrong = mk(
        3,
        SidecarEventPayload::Health(HealthView {
            available: false,
            capability_source: "x".into(),
            freshness: "stale".into(),
            reason: "late".into(),
        }),
    );
    wrong.selection_id = "other".into();
    assert_eq!(reducer.apply(wrong), SidecarEventOutcome::Discarded);

    let mut wrong = mk(
        3,
        SidecarEventPayload::Resolution(sample_trace(SidecarModeChoice::Never)),
    );
    wrong.project_id = "p2".into();
    assert_eq!(reducer.apply(wrong), SidecarEventOutcome::Discarded);

    let mut wrong = mk(
        3,
        SidecarEventPayload::Grant(sample_grant(GrantScope::Once)),
    );
    wrong.session_id = "s2".into();
    assert_eq!(reducer.apply(wrong), SidecarEventOutcome::Discarded);

    let mut wrong = mk(
        3,
        SidecarEventPayload::Grant(sample_grant(GrantScope::Once)),
    );
    wrong.daemon_instance = "d2".into();
    assert_eq!(reducer.apply(wrong), SidecarEventOutcome::Discarded);

    let mut wrong = mk(
        3,
        SidecarEventPayload::Health(HealthView {
            available: false,
            capability_source: "x".into(),
            freshness: "stale".into(),
            reason: "late".into(),
        }),
    );
    wrong.config_generation = 9;
    assert_eq!(reducer.apply(wrong), SidecarEventOutcome::RehydrateRequired);
    assert!(reducer.stale);
    assert!(reducer.invocations.is_empty());

    let mut gap_reducer =
        SidecarReducer::new("d1".into(), "p1".into(), "s1".into(), "sel1".into(), 1);
    assert_eq!(
        gap_reducer.apply(mk(1, SidecarEventPayload::Invocation(inv.clone()))),
        SidecarEventOutcome::Applied
    );
    assert_eq!(
        gap_reducer.apply(mk(10, SidecarEventPayload::Invocation(inv.clone()))),
        SidecarEventOutcome::RehydrateRequired
    );
    assert_eq!(
        gap_reducer.apply(mk(2, SidecarEventPayload::Invocation(inv))),
        SidecarEventOutcome::RehydrateRequired
    );

    let mut dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::Overview);
    let current = authority_snapshot(
        "local",
        "project",
        "session",
        "selection",
        1,
        8,
        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Configured,
        cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask,
    );
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            current.clone(),
        ))),
    );
    assert_eq!(page.session.reducer.entity_version, 1);
    page.session.reducer.grants = vec![sample_grant(GrantScope::Project)];

    page.session.begin_authority_rpc();
    assert!(page.session.busy);
    let mut late = current.clone();
    late.entity_version = 0;
    late.central_invocation_cap = 3;
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            late,
        ))),
    );
    assert_eq!(page.session.policy.value, 8);
    assert_eq!(page.session.reducer.grants.len(), 1);
    assert!(
        !page.session.busy,
        "Late snapshots must settle occupancy of the RPC they complete"
    );

    let mut duplicate = current.clone();
    duplicate.central_invocation_cap = 11;
    duplicate.health_reason = "refreshed".into();
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            duplicate,
        ))),
    );
    assert_eq!(page.session.policy.value, 11);
    assert_eq!(page.session.reducer.grants.len(), 1);
    assert_eq!(
        page.session
            .reducer
            .health
            .as_ref()
            .map(|health| health.reason.as_str()),
        Some("refreshed")
    );

    let mut gap = current;
    gap.entity_version = 9;
    gap.central_invocation_cap = 99;
    page.apply_authoritative_settings_completion(
        &mut dialog.cx,
        Some(Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(
            gap,
        ))),
    );
    assert!(page.session.reducer.stale);
    assert_eq!(page.session.reducer.entity_version, 1);
    assert!(page.session.reducer.grants.is_empty());
    assert!(!page.session.authoritative_mutations);
    assert!(
        page.session.busy,
        "Gap follow-up GET occupies busy until that RPC settles"
    );
    assert!(dialog.cx.sidecar_authority_pending());
}

#[test]
fn image_sidecar_settings_a11y_and_layout_snapshots() {
    let dialog = test_dialog();
    let mut page = page_with(SidecarPageKind::GrantList);
    let mut project_grant = sample_grant(GrantScope::Project);
    project_grant.destination = "https://user:secret@api.openai.com/v1?sig=secret".into();
    page.session.reducer.grants = vec![project_grant];
    page.session.error = Some("cap_exhausted".into());
    page.session.busy = true;
    page.session.save_pending = true;
    page.session.health_refresh_pending = true;
    page.session.conflict = Some("config generation moved".into());
    page.session.remediation = Some(SidecarRemediation::CapExhausted);

    let a11y = page.a11y();
    let rows = page.visible_rows();
    assert_eq!(a11y.effective_policy, "sidecar_invocations_per_session");
    assert_eq!(a11y.effective_value, page.session.policy.value.to_string());
    assert_eq!(a11y.effective_source, page.session.policy.source_label());
    assert_eq!(a11y.busy, true);
    assert_eq!(a11y.error.as_deref(), Some("cap_exhausted"));
    assert_eq!(
        a11y.project_grant_warning.as_deref(),
        Some(PROJECT_GRANT_WARNING)
    );
    let focused = rows.get(page.session.cursor.get()).unwrap();
    assert_eq!(a11y.focused_label, focused.label);
    assert_eq!(a11y.focused_value, focused.value);
    assert_eq!(a11y.non_color_state, focused.state);
    assert_eq!(
        a11y.destination,
        focused.destination.clone().unwrap_or_default()
    );
    assert_eq!(a11y.scope, focused.scope.clone().unwrap_or_default());
    assert_eq!(a11y.destination, "https://api.openai.com/v1");

    for (w, h, token) in [
        (100, 30, "Layout: Full"),
        (80, 24, "Layout: Compact"),
        (60, 16, "Destination grants"),
        (40, 10, "too small"),
    ] {
        let joined = render_page_lines(&page, &dialog, w, h).join("\n");
        assert!(
            joined.contains(token),
            "expected {token} at {w}x{h}: {joined}"
        );
    }

    page.session
        .rebind_identity("d2".into(), "p2".into(), "s2".into(), "sel2".into(), 7);
    assert!(page.session.reducer.grants.is_empty());
    assert!(page.session.confirm_revoke.borrow().is_none());
    assert!(page.session.error.is_none());
    assert!(!page.session.authoritative_snapshot);
    assert!(!page.session.authoritative_mutations);
    assert!(!page.session.principal.can_mutate());
    assert!(page.session.form.models.is_empty());
    assert_eq!(page.session.form.override_pair, None);
    assert!(!page.session.save_pending);
    assert!(!page.session.health_refresh_pending);
    assert_eq!(page.session.reducer.config_generation, 7);
    assert_eq!(
        page.session.reducer.apply(SidecarEvent {
            daemon_instance: "local".into(),
            project_id: "project".into(),
            session_id: "session".into(),
            selection_id: "selection".into(),
            config_generation: 1,
            entity_version: 1,
            payload: SidecarEventPayload::Health(HealthView {
                available: true,
                capability_source: "configured".into(),
                freshness: "fresh".into(),
                reason: "late completion".into(),
            }),
        }),
        SidecarEventOutcome::Discarded,
        "a completion for the previous identity must remain inert after rebind"
    );

    let empty = page_with(SidecarPageKind::GrantList);
    let joined = render_page_lines(&empty, &dialog, 80, 24).join("\n");
    assert!(joined.contains("No destination grants"));

    let mut err = page_with(SidecarPageKind::Overview);
    err.session.remediation = Some(SidecarRemediation::MissingCredential);
    let joined = render_page_lines(&err, &dialog, 80, 24).join("\n");
    assert!(joined.contains(REASON_MISSING_CREDENTIAL));

    let mut page = page_with(SidecarPageKind::Overview);
    page.handle_key(&mut test_dialog(), press(KeyCode::Down));
    assert_eq!(page.session.cursor.get(), 1);
    page.handle_key(&mut test_dialog(), press(KeyCode::Up));
    assert_eq!(page.session.cursor.get(), 0);
}

#[test]
fn image_sidecar_settings_cursor_and_a11y_follow_rendered_rows() {
    let mut page = page_with(SidecarPageKind::GrantList);
    page.session.reducer.grants = vec![sample_grant(GrantScope::Project)];
    page.session.cursor.set(99);

    // A dynamic reducer change can shrink the list after the cursor was set.
    // A11y, rendering, and keyboard dispatch must use the same clamped row.
    page.session.reducer.grants.clear();
    let a11y = page.a11y();
    assert_eq!(
        a11y.focused_label,
        "Effective: 32 source=configured hard_ceiling=128"
    );
    assert!(a11y.project_grant_warning.is_none());
    page.handle_key(&mut test_dialog(), press(KeyCode::Down));
    assert_eq!(page.session.cursor.get(), page.max_cursor());

    // Off-page grants and resolver traces are not a11y fallbacks. Only the
    // viewport-clipped focused typed row may supply these sensitive facts.
    page.session.reducer.grants = vec![sample_grant(GrantScope::Project)];
    page.session.cursor.set(3);
    page.session.a11y_viewport.set((2, 2));
    let a11y = page.a11y();
    assert!(a11y.destination.is_empty());
    assert!(a11y.project_grant_warning.is_none());

    let mut resolver = page_with(SidecarPageKind::ResolverDetail);
    resolver.session.a11y_viewport.set((0, 1));
    let a11y = resolver.a11y();
    assert!(a11y.destination.is_empty());
}

#[test]
fn image_sidecar_a11y_projects_focused_invocation_error_and_project_warning() {
    let mut invocations = page_with(SidecarPageKind::InvocationList);
    let mut invocation = sample_invocation();
    invocation.safe_error = Some("provider_failure".into());
    invocations.session.reducer.invocations = vec![invocation];
    invocations.session.error = Some("page_error".into());
    invocations.session.cursor.set(0);

    let invocation_a11y = invocations.a11y();
    assert_eq!(invocation_a11y.focused_label, "inv-1");
    assert_eq!(invocation_a11y.error.as_deref(), Some("provider_failure"));
    assert!(invocation_a11y.project_grant_warning.is_none());

    let mut grants = page_with(SidecarPageKind::GrantList);
    grants.session.reducer.grants = vec![sample_grant(GrantScope::Project)];
    grants.session.cursor.set(0);

    let grant_a11y = grants.a11y();
    assert_eq!(grant_a11y.focused_label, "grant-1");
    assert_eq!(
        grant_a11y.project_grant_warning.as_deref(),
        Some(PROJECT_GRANT_WARNING)
    );
}

#[test]
fn image_sidecar_settings_create_grant_requires_current_destination_and_once_binding() {
    let mut page = page_with(SidecarPageKind::GrantEditor);
    let create = page
        .named_actions()
        .into_iter()
        .find(|(action, _, _)| matches!(action, SidecarAction::CreateGrant))
        .unwrap();
    assert!(!create.1);
    assert_eq!(create.2, Some(REASON_INVOCATION_NOT_FOUND));
    page.handle_pointer_control(
        &mut test_dialog(),
        SettingsPointerAction::Sidecar(SidecarAction::CreateGrant),
    );
    assert!(page.session.reducer.grants.is_empty());

    page.session.form.draft_scope = GrantScope::Session;
    page.session.reducer.resolution.as_mut().unwrap().available = false;
    page.session.reducer.resolution.as_mut().unwrap().reason = "candidate_unavailable".into();
    let create = page
        .named_actions()
        .into_iter()
        .find(|(action, _, _)| matches!(action, SidecarAction::CreateGrant))
        .unwrap();
    assert!(!create.1);
    assert_eq!(create.2, Some(REASON_DESTINATION_DENIED));
    page.handle_pointer_control(
        &mut test_dialog(),
        SettingsPointerAction::Sidecar(SidecarAction::CreateGrant),
    );
    assert!(page.session.reducer.grants.is_empty());

    page.session.reducer.resolution.as_mut().unwrap().available = true;
    page.session.reducer.resolution.as_mut().unwrap().reason = "selected".into();
    page.session.form.draft_scope = GrantScope::Once;
    page.session.reducer.invocations = vec![sample_invocation()];
    page.session.selected_invocation = Some("inv-1".into());
    let create = page
        .named_actions()
        .into_iter()
        .find(|(action, _, _)| matches!(action, SidecarAction::CreateGrant))
        .unwrap();
    assert!(create.1);
    assert_eq!(create.2, None);
    page.handle_pointer_control(
        &mut test_dialog(),
        SettingsPointerAction::Sidecar(SidecarAction::CreateGrant),
    );
    assert!(page.session.reducer.grants.is_empty());
    assert!(page.session.error.is_none());
    assert!(page.session.busy);
}

#[test]
fn image_sidecar_settings_no_policy_logic_in_ui() {
    let src = include_str!("mod.rs");
    for needle in [
        "SidecarResolver::",
        "evaluate_egress_authority",
        "DestinationGrantStore",
        "DestinationGrant::authorizes",
        ".authorizes(",
    ] {
        assert!(
            !src.contains(needle),
            "sidecar settings UI must not contain policy symbol {needle}"
        );
    }
    let _ = SidecarFormState::default().to_selection_config();
}

#[test]
fn image_sidecar_settings_pointer_surface_contract() {
    let dialog = test_dialog();
    for kind in SidecarPageKind::ALL {
        let page = page_with(kind);
        assert_eq!(page.pointer_surface_kind(), kind.surface());
        let _ = render_page_lines(&page, &dialog, 100, 40);
    }

    let mut overview = page_with(SidecarPageKind::Overview);
    let before = overview.session.form.mode;
    let mut dialog = test_dialog();
    overview.handle_pointer_scroll(
        &mut dialog,
        crate::tui::settings::shell::SettingsScrollRegionId("sidecar"),
        1,
    );
    assert_eq!(overview.session.form.mode, before);
    assert_eq!(overview.session.cursor.get(), 1);

    let mut grants = page_with(SidecarPageKind::GrantList);
    grants.session.reducer.grants = vec![sample_grant(GrantScope::Once)];
    grants.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    assert!(grants.session.confirm_revoke.borrow().is_some());
    grants.handle_pointer_scroll(
        &mut dialog,
        crate::tui::settings::shell::SettingsScrollRegionId("sidecar"),
        1,
    );
    assert!(grants.session.confirm_revoke.borrow().is_none());
    assert!(!grants.session.reducer.grants[0].revoked);

    grants.handle_key(&mut dialog, press(KeyCode::Enter));
    assert!(!grants.session.reducer.grants[0].revoked);
    assert!(grants.session.confirm_revoke.borrow().is_none());

    grants.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    grants.cancel_pointer_transients();
    assert!(grants.session.confirm_revoke.borrow().is_none());

    let surfaces: std::collections::HashSet<_> =
        SettingsPointerSurfaceKind::ALL.into_iter().collect();
    for kind in SidecarPageKind::ALL {
        assert!(surfaces.contains(&kind.surface()));
    }
}

#[test]
fn image_sidecar_settings_state_action_registry() {
    let dialog = test_dialog();
    let mut seen_surfaces = std::collections::HashSet::new();
    let mut seen_actions = std::collections::HashSet::new();
    for kind in SidecarPageKind::ALL {
        for (w, h) in [(100, 30), (80, 24), (60, 16)] {
            let mut page = page_with(kind);
            if kind == SidecarPageKind::ModeEditor {
                page.session.conflict = Some("reload before reapplying".into());
            }
            page.session.reducer.grants = vec![sample_grant(GrantScope::Project)];
            page.session.reducer.invocations = vec![sample_invocation()];
            page.session.form.models = vec![SidecarModelOption {
                provider: "openai".into(),
                model: "gpt-4o".into(),
                configured: true,
                image_capable: true,
                fresh: true,
            }];
            if kind == SidecarPageKind::GrantList {
                *page.session.confirm_revoke.borrow_mut() = Some(PendingRevoke {
                    grant_id: "grant-1".into(),
                    version: 1,
                    layout: None,
                });
            }
            seen_surfaces.insert(page.pointer_surface_kind());
            let joined = render_page_lines(&page, &dialog, w, h).join("\n");
            if kind == SidecarPageKind::GrantList && w >= 60 {
                assert!(
                    joined.contains("Revoke grant? [Revoke grant] [Cancel]"),
                    "missing confirmation at {w}x{h}: {joined}"
                );
            }
            for (action, enabled, reason) in page.named_actions() {
                seen_actions.insert(std::mem::discriminant(&action));
                if !enabled {
                    assert!(
                        reason.is_some(),
                        "disabled action {:?} needs a stable reason",
                        action
                    );
                }
            }
        }
    }
    assert_eq!(seen_surfaces.len(), 11);

    let mut grants = page_with(SidecarPageKind::GrantList);
    grants.session.reducer.grants = vec![sample_grant(GrantScope::Once)];
    let mut dialog = test_dialog();
    grants.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(SidecarGrantId(
            "grant-1".into(),
        ))),
    );
    grants.handle_pointer_control(
        &mut dialog,
        SettingsPointerAction::Sidecar(SidecarAction::ConfirmRevokeGrant(
            SidecarGrantId("other".into()),
            ConfirmationChoice::Confirm,
        )),
    );
    assert!(!grants.session.reducer.grants[0].revoked);

    *grants.session.confirm_revoke.borrow_mut() = Some(PendingRevoke {
        grant_id: "grant-1".into(),
        version: 1,
        layout: None,
    });
    grants
        .session
        .rebind_identity("d".into(), "p".into(), "s".into(), "sel".into(), 1);
    assert!(grants.session.confirm_revoke.borrow().is_none());

    *grants.session.confirm_revoke.borrow_mut() = Some(PendingRevoke {
        grant_id: "grant-1".into(),
        version: 1,
        layout: None,
    });
    grants.session.reducer.grants = vec![sample_grant(GrantScope::Once)];
    grants.cancel_pointer_transients();
    assert!(grants.session.confirm_revoke.borrow().is_none());
    assert!(!grants.session.reducer.grants[0].revoked);

    assert_eq!(
        seen_actions.len(),
        20,
        "every SidecarAction variant must be emitted by the state registry"
    );
}
