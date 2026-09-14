//! Controlled daemon settlement tests for authored agent packages.

use std::sync::Arc;

use cockpit_config::providers::{
    CapabilityStatus, ModelCapabilities, ModelEntry, ModelLocation, ModelTrust, ProviderEntry,
    ProvidersConfig,
};
use cockpit_proto::{
    ApplyAuthoredAgentPackageOutcome, ApplyAuthoredAgentPackageRequest,
    AuthoredAgentPackageReceiptQuery, AuthoredAgentReceiptStatus, AuthoredAgentRejectReason,
    Request, Response,
};

use super::dispatch::handle_request;
use super::*;

fn authored_test_providers() -> ProvidersConfig {
    let mut providers = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        template: Some("vendor".into()),
        url: "http://localhost:1/v1".to_string(),
        trust: Some(ModelTrust::Trusted),
        ..Default::default()
    };
    provider.models.push(ModelEntry {
        id: "exact-a".into(),
        trust: Some(ModelTrust::Trusted),
        location: Some(ModelLocation::Remote),
        capabilities: ModelCapabilities {
            context_tokens: Some(128_000),
            tool_calling: CapabilityStatus::Supported,
            ..ModelCapabilities::default()
        },
        ..Default::default()
    });
    providers
        .providers
        .insert("vendor-profile".into(), provider);
    providers
}

fn authored_test_ctx() -> Arc<DaemonContext> {
    let tmp = tempfile::tempdir().expect("authored daemon tempdir");
    let db = crate::db::Db::open_in_memory().expect("in-memory db");
    let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
    let ctx = DaemonContext::new(
        db,
        locks,
        DaemonPaths {
            socket: tmp.path().join("cockpit.sock"),
            pid_file: tmp.path().join("cockpit.pid"),
            ephemeral: true,
        },
        crate::daemon::terminal::test_host_factory(),
        crate::daemon::config_source::ConfigSource::fixed(
            authored_test_providers(),
            cockpit_config::extended::ExtendedConfig::default(),
        ),
    );
    let generation = ctx.host_capabilities.begin_refresh();
    let mut snapshot = crate::daemon::session_worker::sandbox_capability_snapshot(
        cockpit_proto::FeatureCapabilityState::Available,
        cockpit_proto::FeatureCapabilityState::Available,
    );
    snapshot.generation = generation;
    ctx.host_capabilities.publish(snapshot);
    Arc::new(ctx)
}

async fn fetch_projection(
    ctx: &Arc<DaemonContext>,
    state: &mut MutableClientState,
) -> cockpit_proto::AgentAuthoringProjection {
    match handle_request(Request::GetAgentAuthoringProjection, state, ctx)
        .await
        .expect("projection transport")
    {
        Response::AgentAuthoringProjection(projection) => projection,
        other => panic!("unexpected projection response: {other:?}"),
    }
}

fn package_from_projection(
    projection: &cockpit_proto::AgentAuthoringProjection,
) -> cockpit_proto::AuthoredAgentPackageDraft {
    use crate::authoring_draft::{AgentAuthoringDraft, build_package_draft};

    let mut draft = AgentAuthoringDraft::from_projection(projection);
    for index in draft.pending_trust_route_indices(projection) {
        draft.trust_confirmations[index] = true;
    }
    build_package_draft(projection, &draft).expect("canonical package draft")
}

async fn apply_authored(
    ctx: &Arc<DaemonContext>,
    state: &mut MutableClientState,
    request: ApplyAuthoredAgentPackageRequest,
) -> ApplyAuthoredAgentPackageOutcome {
    match handle_request(Request::ApplyAuthoredAgentPackage(request), state, ctx)
        .await
        .expect("apply transport")
    {
        Response::AuthoredAgentPackage(outcome) => outcome,
        other => panic!("unexpected apply response: {other:?}"),
    }
}

async fn receipt_for(
    ctx: &Arc<DaemonContext>,
    state: &mut MutableClientState,
    client_operation_id: &str,
) -> Option<cockpit_proto::ApplyAuthoredAgentPackageReceipt> {
    match handle_request(
        Request::GetAuthoredAgentPackageReceipt(AuthoredAgentPackageReceiptQuery {
            client_operation_id: client_operation_id.into(),
        }),
        state,
        ctx,
    )
    .await
    .expect("receipt transport")
    {
        Response::AuthoredAgentPackageReceipt(receipt) => receipt,
        other => panic!("unexpected receipt response: {other:?}"),
    }
}

#[tokio::test]
async fn authored_agent_controlled_daemon_settlement_matrix() {
    let ctx = authored_test_ctx();
    let mut state = MutableClientState::detached_for_test();

    let miss = receipt_for(&ctx, &mut state, "never-submitted").await;
    assert!(
        miss.is_none(),
        "absent operations must miss instead of fabricating unknown"
    );

    let projection = fetch_projection(&ctx, &mut state).await;
    assert!(
        !projection.policy.routes.is_empty(),
        "daemon projection must expose configured routes"
    );
    let package = package_from_projection(&projection);

    let stale = apply_authored(
        &ctx,
        &mut state,
        ApplyAuthoredAgentPackageRequest {
            client_operation_id: "stale-policy".into(),
            expected_policy_revision: "ab".repeat(32),
            package: package.clone(),
            onboarding: None,
            validate_only: false,
        },
    )
    .await;
    assert!(matches!(
        stale,
        ApplyAuthoredAgentPackageOutcome::PolicyRevisionConflict { .. }
    ));

    let operation_id = "authored-settlement-matrix";
    let request = ApplyAuthoredAgentPackageRequest {
        client_operation_id: operation_id.into(),
        expected_policy_revision: projection.policy.policy_revision.clone(),
        package,
        onboarding: None,
        validate_only: false,
    };
    let committed = apply_authored(&ctx, &mut state, request.clone()).await;
    let committed = match committed {
        ApplyAuthoredAgentPackageOutcome::Receipt(receipt)
            if receipt.status == AuthoredAgentReceiptStatus::Committed =>
        {
            receipt
        }
        other => panic!("apply must commit: {other:?}"),
    };

    let queried = receipt_for(&ctx, &mut state, operation_id)
        .await
        .expect("committed receipt");
    assert_eq!(committed.installation_id, queried.installation_id);

    let mut reopened_state = MutableClientState::detached_for_test();
    let after_close = receipt_for(&ctx, &mut reopened_state, operation_id)
        .await
        .expect("receipt after shell close");
    assert_eq!(committed.installation_id, after_close.installation_id);

    let replayed = apply_authored(&ctx, &mut state, request).await;
    let replayed = match replayed {
        ApplyAuthoredAgentPackageOutcome::Receipt(receipt)
            if receipt.status == AuthoredAgentReceiptStatus::Committed =>
        {
            receipt
        }
        other => panic!("duplicate create must replay terminal receipt: {other:?}"),
    };
    assert_eq!(committed.installation_id, replayed.installation_id);
    assert!(committed.default_selected);

    let recovered = crate::daemon::agent_authoring::recover_authored_agent_package_journals(&ctx)
        .await
        .expect("daemon recovery");
    assert_eq!(recovered, 0, "terminal journals must not be re-executed");

    let installations = ctx
        .db
        .list_agent_installations(
            cockpit_db::db::agent_installations::AgentInstallationScope::Global,
            None,
        )
        .await
        .expect("installation inventory");
    assert_eq!(
        installations.len(),
        1,
        "duplicate create/reopen must not mint a second installation"
    );
    let default = ctx
        .db
        .default_agent_installation()
        .await
        .expect("default installation lookup");
    assert_eq!(
        default.map(|id| id.to_string()),
        committed.installation_id.clone(),
        "terminal receipt must remain the sole default installation"
    );
}

#[tokio::test]
async fn authored_agent_two_client_draft_revision_race_fails_closed() {
    let ctx = authored_test_ctx();
    let mut first_client = MutableClientState::detached_for_test();
    let projection = fetch_projection(&ctx, &mut first_client).await;
    let stale_package = package_from_projection(&projection);

    let now = crate::workspace_lease::now_unix_ms();
    ctx.db
        .cas_authored_agent_package_draft(
            stale_package.name.clone(),
            None,
            "other-client-draft".into(),
            "a".repeat(64),
            now,
        )
        .await
        .expect("second client draft CAS");

    let outcome = apply_authored(
        &ctx,
        &mut first_client,
        ApplyAuthoredAgentPackageRequest {
            client_operation_id: "stale-draft-race".into(),
            expected_policy_revision: projection.policy.policy_revision.clone(),
            package: stale_package,
            onboarding: None,
            validate_only: false,
        },
    )
    .await;
    assert!(matches!(
        outcome,
        ApplyAuthoredAgentPackageOutcome::Rejected {
            reason: AuthoredAgentRejectReason::StaleDraft,
            ..
        }
    ));
}

#[tokio::test]
async fn authored_agent_restart_replays_terminal_receipt_without_duplicate_install() {
    let ctx = authored_test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let projection = fetch_projection(&ctx, &mut state).await;
    let package = package_from_projection(&projection);
    let operation_id = "authored-restart-receipt";
    let request = ApplyAuthoredAgentPackageRequest {
        client_operation_id: operation_id.into(),
        expected_policy_revision: projection.policy.policy_revision.clone(),
        package,
        onboarding: None,
        validate_only: false,
    };
    let committed = apply_authored(&ctx, &mut state, request.clone()).await;
    let committed = match committed {
        ApplyAuthoredAgentPackageOutcome::Receipt(receipt)
            if receipt.status == AuthoredAgentReceiptStatus::Committed =>
        {
            receipt
        }
        other => panic!("apply must commit: {other:?}"),
    };

    let recovered = crate::daemon::agent_authoring::recover_authored_agent_package_journals(&ctx)
        .await
        .expect("daemon recovery after restart");
    assert_eq!(recovered, 0, "terminal journals must not be re-executed");

    let mut restarted_state = MutableClientState::detached_for_test();
    let replayed = receipt_for(&ctx, &mut restarted_state, operation_id)
        .await
        .expect("lost-receipt reconciliation");
    assert_eq!(committed.installation_id, replayed.installation_id);
    assert_eq!(replayed.status, AuthoredAgentReceiptStatus::Committed);

    let duplicate = apply_authored(&ctx, &mut restarted_state, request).await;
    let duplicate = match duplicate {
        ApplyAuthoredAgentPackageOutcome::Receipt(receipt)
            if receipt.status == AuthoredAgentReceiptStatus::Committed =>
        {
            receipt
        }
        other => panic!("duplicate create must replay terminal receipt: {other:?}"),
    };
    assert_eq!(committed.installation_id, duplicate.installation_id);
}

#[tokio::test]
async fn authored_agent_pending_journal_surfaces_exact_pending_receipt() {
    let ctx = authored_test_ctx();
    let mut state = MutableClientState::detached_for_test();
    let projection = fetch_projection(&ctx, &mut state).await;
    let package = package_from_projection(&projection);
    let operation_id = "authored-pending-receipt";
    let now = crate::workspace_lease::now_unix_ms();
    let request = ApplyAuthoredAgentPackageRequest {
        client_operation_id: operation_id.into(),
        expected_policy_revision: projection.policy.policy_revision.clone(),
        package,
        onboarding: None,
        validate_only: false,
    };
    let fence = crate::daemon::agent_authoring::publication_fence_for_request(&request)
        .expect("publication fence");
    let providers = ctx.config_source().load(&ctx.canonical_cwd).unwrap().0;
    let catalog = crate::daemon::agent_catalog::preferred_catalog()
        .await
        .unwrap();
    let snapshot =
        crate::onboarding_agent::policy_snapshot(&providers, catalog.origin, &catalog.revision);
    let canonical = crate::onboarding_agent::canonicalize_authored_package(
        &request.package,
        &snapshot,
        &providers,
        &catalog.index,
    )
    .expect("canonical package");
    let review_json = serde_json::to_string(&canonical.review).unwrap();
    let package_files_json = {
        let encoded = canonical
            .files
            .iter()
            .map(|(path, bytes)| (path.clone(), crate::intel::hex_lower(bytes)))
            .collect::<std::collections::BTreeMap<_, _>>();
        serde_json::to_string(&encoded).unwrap()
    };
    let _ = ctx
        .db
        .begin_authored_agent_package_journal(
            cockpit_db::db::authored_agent_packages::AuthoredAgentPackageJournalRow {
                owner_digest: fence.owner_digest.clone(),
                client_operation_id: operation_id.into(),
                request_hash: fence.request_hash.to_vec(),
                fencing_generation: fence.fencing_generation,
                policy_revision: snapshot.policy_revision.clone(),
                package_digest: canonical.digest.clone(),
                draft_revision: canonical.digest.clone(),
                expected_draft_revision: request.package.draft_revision.clone(),
                agent_name: request.package.name.clone(),
                source_locator: request.package.source.source_locator.clone(),
                source_pin: request.package.source.pin.clone(),
                require_third_party: false,
                third_party_trust_confirmed: false,
                make_default: request.package.make_default,
                sidecar_intent_json: "{}".into(),
                package_files_json,
                review_json,
                installation_id: None,
                default_selected: request.package.make_default,
                onboarding_run_id: None,
                onboarding_attempt_id: None,
                onboarding_stage_revision: None,
                settlement_phase:
                    cockpit_db::db::authored_agent_packages::AUTHORED_PACKAGE_SETTLEMENT_PENDING
                        .to_string(),
                terminal_response_json: None,
                created_at_unix_ms: now,
            },
        )
        .await
        .expect("pending journal");

    let pending = receipt_for(&ctx, &mut state, operation_id)
        .await
        .expect("pending receipt");
    assert_eq!(pending.status, AuthoredAgentReceiptStatus::Pending);
    assert_eq!(pending.package_digest, canonical.digest);
}
