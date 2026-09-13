//! Daemon apply/reconcile for authored agent packages.

use anyhow::{Context, Result};
use cockpit_proto::{
    AgentAuthoringProjection, ApplyAuthoredAgentPackageOutcome, ApplyAuthoredAgentPackageReceipt,
    ApplyAuthoredAgentPackageRequest, AuthoredAgentPackageReceiptQuery, AuthoredAgentReceiptStatus,
    AuthoredAgentRejectReason, AuthoredAgentReview, Response,
};

use super::server::DaemonContext;

pub async fn get_projection(ctx: &DaemonContext) -> Result<AgentAuthoringProjection> {
    let providers = ctx
        .config_source()
        .load(&ctx.canonical_cwd)
        .context("loading daemon provider configuration")?
        .0;
    let catalog = crate::daemon::agent_catalog::preferred_catalog().await?;
    crate::onboarding_agent::authoring_projection(
        &providers,
        &catalog.index,
        catalog.origin,
        &catalog.revision,
    )
}

pub struct AuthoredApplyFence {
    pub owner_digest: String,
    pub request_hash: [u8; 32],
    pub fencing_generation: i64,
}

pub async fn apply_package(
    ctx: &DaemonContext,
    request: ApplyAuthoredAgentPackageRequest,
    fence: Option<AuthoredApplyFence>,
) -> Result<ApplyAuthoredAgentPackageOutcome> {
    let _lock = crate::daemon::server::CONFIG_PUBLICATION_RPC_LOCK
        .lock()
        .await;
    apply_package_under_publication_lock(ctx, request, fence).await
}

pub async fn apply_package_under_publication_lock(
    ctx: &DaemonContext,
    request: ApplyAuthoredAgentPackageRequest,
    fence: Option<AuthoredApplyFence>,
) -> Result<ApplyAuthoredAgentPackageOutcome> {
    if let Some(fence) = &fence
        && let Some(journal) = ctx
            .db
            .authored_agent_package_journal(
                fence.owner_digest.clone(),
                request.client_operation_id.clone(),
            )
            .await?
    {
        if journal.request_hash.as_slice() == fence.request_hash.as_slice() {
            if let Ok(Response::AuthoredAgentPackage(outcome)) =
                serde_json::from_str(&journal.terminal_response_json)
            {
                return Ok(outcome);
            }
        }
    }
    let providers = ctx
        .config_source()
        .load(&ctx.canonical_cwd)
        .context("loading daemon provider configuration")?
        .0;
    let catalog = crate::daemon::agent_catalog::preferred_catalog().await?;
    let snapshot =
        crate::onboarding_agent::policy_snapshot(&providers, catalog.origin, &catalog.revision);
    if request.expected_policy_revision != snapshot.policy_revision
        || request.package.policy_revision != snapshot.policy_revision
    {
        let projection = crate::onboarding_agent::authoring_projection(
            &providers,
            &catalog.index,
            catalog.origin,
            &catalog.revision,
        )?;
        return Ok(ApplyAuthoredAgentPackageOutcome::PolicyRevisionConflict { projection });
    }
    if let Some(correlation) = &request.onboarding {
        let current = ctx.db.onboarding_snapshot().await?;
        let live = current.as_ref().is_some_and(|row| {
            row.run_id == correlation.run_id
                && row.attempt_id == correlation.attempt_id
                && row.revision == correlation.stage_revision
                && row.stage == crate::db::onboarding::OnboardingStage::Agent
        });
        if !live {
            return Ok(ApplyAuthoredAgentPackageOutcome::Rejected {
                reason: AuthoredAgentRejectReason::StaleDraft,
                message: "onboarding correlation does not match the active agent-stage run; query the exact operation instead of retrying create".into(),
                projection: None,
            });
        }
    }
    let package = match crate::onboarding_agent::canonicalize_authored_package(
        &request.package,
        &snapshot,
        &providers,
        &catalog.index,
    ) {
        Ok(package) => package,
        Err(error) => {
            return Ok(ApplyAuthoredAgentPackageOutcome::Rejected {
                reason: error.reason,
                message: error.message,
                projection: None,
            });
        }
    };
    let now = crate::workspace_lease::now_unix_ms();
    let current_draft = ctx
        .db
        .authored_agent_package_draft(request.package.name.clone())
        .await
        .context("loading authored draft revision")?;
    let draft_matches = match (
        request.package.draft_revision.as_deref(),
        current_draft
            .as_ref()
            .map(|row| row.draft_revision.as_str()),
    ) {
        (None, None) => true,
        (Some(expected), Some(actual)) => expected == actual,
        _ => false,
    };
    if !draft_matches {
        return Ok(ApplyAuthoredAgentPackageOutcome::Rejected {
            reason: AuthoredAgentRejectReason::StaleDraft,
            message: "authored draft revision does not match the last authoritative draft; edit/retry the current revision".into(),
            projection: None,
        });
    }
    let require_third_party = matches!(
        request.package.source.kind,
        cockpit_proto::AgentAuthoringSourceKind::ThirdParty
    );
    let service = ctx.agent_installation_service()?;
    let install = service
        .commit_authored_package(
            request.client_operation_id.clone(),
            &request.package.name,
            request.package.source.source_locator.clone(),
            request.package.source.pin.clone(),
            require_third_party,
            request.package.source.third_party_trust_confirmed,
            package.files.clone(),
            package.digest.clone(),
            now,
        )
        .await;
    let (operation_id, installation_id) = match install {
        cockpit_proto::AgentInstallationResultV1::Receipt {
            status:
                cockpit_proto::AgentInstallationReceiptStatusV1::Created
                | cockpit_proto::AgentInstallationReceiptStatusV1::Installed
                | cockpit_proto::AgentInstallationReceiptStatusV1::Bound,
            operation_id,
            installation_id,
            ..
        } => (operation_id, installation_id),
        cockpit_proto::AgentInstallationResultV1::Error { error } => {
            return Ok(ApplyAuthoredAgentPackageOutcome::Rejected {
                reason: AuthoredAgentRejectReason::IncompletePackage,
                message: error.message,
                projection: None,
            });
        }
        other => {
            return Ok(ApplyAuthoredAgentPackageOutcome::Rejected {
                reason: AuthoredAgentRejectReason::IncompletePackage,
                message: format!("installation did not complete: {other:?}"),
                projection: None,
            });
        }
    };
    if let Err(error) = crate::onboarding_agent::publish_authored_sidecar_selection(
        &request.package.sidecars,
        &providers,
    ) {
        return Ok(ApplyAuthoredAgentPackageOutcome::Rejected {
            reason: AuthoredAgentRejectReason::UnapprovedRemoteSidecarEgress,
            message: error.to_string(),
            projection: None,
        });
    }
    let default_selected = request.package.make_default;
    if default_selected
        && let Some(installation_id) = installation_id.as_deref()
        && let Ok(id) = uuid::Uuid::parse_str(installation_id)
    {
        ctx.db
            .set_default_agent_installation(id, now)
            .await
            .context("selecting default authored agent installation")?;
    }
    let cas_ok = ctx
        .db
        .cas_authored_agent_package_draft(
            request.package.name.clone(),
            request.package.draft_revision.clone(),
            package.digest.clone(),
            package.digest.clone(),
            now,
        )
        .await
        .context("committing authored draft revision")?;
    if !cas_ok {
        return Ok(ApplyAuthoredAgentPackageOutcome::Rejected {
            reason: AuthoredAgentRejectReason::StaleDraft,
            message: "authored draft revision does not match the last authoritative draft; edit/retry the current revision".into(),
            projection: None,
        });
    }
    let mut receipt = crate::onboarding_agent::committed_receipt(
        request.client_operation_id.clone(),
        &package,
        &snapshot,
        installation_id.clone(),
        default_selected,
    );
    if let Ok(id) = uuid::Uuid::parse_str(&operation_id) {
        receipt.receipt_id = id;
    }
    let outcome = ApplyAuthoredAgentPackageOutcome::Receipt(receipt);
    if let Some(fence) = fence {
        let terminal_response_json =
            serde_json::to_string(&Response::AuthoredAgentPackage(outcome.clone()))
                .context("encoding authored package receipt")?;
        ctx.db
            .record_authored_agent_package_journal(
                crate::db::authored_agent_packages::AuthoredAgentPackageJournalRow {
                    owner_digest: fence.owner_digest,
                    client_operation_id: request.client_operation_id,
                    request_hash: fence.request_hash.to_vec(),
                    fencing_generation: fence.fencing_generation,
                    policy_revision: snapshot.policy_revision,
                    package_digest: package.digest.clone(),
                    draft_revision: package.digest.clone(),
                    installation_id,
                    default_selected,
                    onboarding_run_id: request
                        .onboarding
                        .as_ref()
                        .map(|row| row.run_id.to_string()),
                    onboarding_attempt_id: request
                        .onboarding
                        .as_ref()
                        .map(|row| row.attempt_id.to_string()),
                    onboarding_stage_revision: request
                        .onboarding
                        .as_ref()
                        .map(|row| i64::try_from(row.stage_revision).unwrap_or(i64::MAX)),
                    terminal_response_json,
                    created_at_unix_ms: now,
                },
            )
            .await
            .context("recording authored package journal")?;
    }
    Ok(outcome)
}

pub async fn recover_authored_agent_package_journals(ctx: &DaemonContext) -> Result<u64> {
    let rows = ctx.db.list_authored_agent_package_journals().await?;
    let mut recovered = 0_u64;
    for row in rows {
        let hash: [u8; 32] = row
            .request_hash
            .as_slice()
            .try_into()
            .context("authored package journal request hash")?;
        if matches!(
            ctx.db
                .local_operation_settlement(
                    row.owner_digest.clone(),
                    row.client_operation_id.clone()
                )
                .await?,
            Some(crate::db::local_operation_receipts::LocalOperationSettlement::Pending(_))
        ) {
            ctx.db
                .finish_local_operation(
                    row.owner_digest,
                    row.client_operation_id,
                    hash,
                    row.fencing_generation,
                    "terminal_success".into(),
                    row.terminal_response_json,
                )
                .await
                .context("finishing authored package local operation from journal")?;
            recovered = recovered.saturating_add(1);
        }
    }
    Ok(recovered)
}

pub async fn receipt(
    ctx: &DaemonContext,
    owner: &str,
    query: AuthoredAgentPackageReceiptQuery,
) -> Result<ApplyAuthoredAgentPackageReceipt> {
    let Some(settlement) = ctx
        .db
        .local_operation_settlement(owner.to_owned(), query.client_operation_id.clone())
        .await?
    else {
        return Ok(unknown_receipt(&query.client_operation_id, None));
    };
    match settlement {
        crate::db::local_operation_receipts::LocalOperationSettlement::TerminalSuccess(
            identity,
            json,
        ) if identity.operation_kind == "apply_authored_agent_package" => {
            match serde_json::from_str::<Response>(&json) {
                Ok(Response::AuthoredAgentPackage(ApplyAuthoredAgentPackageOutcome::Receipt(
                    receipt,
                ))) => Ok(receipt),
                Ok(Response::AuthoredAgentPackage(
                    ApplyAuthoredAgentPackageOutcome::Rejected { .. },
                )) => Ok(unknown_receipt(&query.client_operation_id, None)),
                _ => Ok(unknown_receipt(&query.client_operation_id, None)),
            }
        }
        crate::db::local_operation_receipts::LocalOperationSettlement::Pending(_) => {
            if let Some(journal) = ctx
                .db
                .authored_agent_package_journal(owner.to_owned(), query.client_operation_id.clone())
                .await?
                && let Ok(Response::AuthoredAgentPackage(
                    ApplyAuthoredAgentPackageOutcome::Receipt(receipt),
                )) = serde_json::from_str(&journal.terminal_response_json)
            {
                return Ok(receipt);
            }
            Ok(unknown_receipt(&query.client_operation_id, None))
        }
        _ => Ok(unknown_receipt(&query.client_operation_id, None)),
    }
}

fn unknown_receipt(
    client_operation_id: &str,
    receipt_id: Option<uuid::Uuid>,
) -> ApplyAuthoredAgentPackageReceipt {
    ApplyAuthoredAgentPackageReceipt {
        client_operation_id: client_operation_id.to_string(),
        receipt_id: receipt_id.unwrap_or(uuid::Uuid::nil()),
        status: AuthoredAgentReceiptStatus::Unknown,
        package_digest: String::new(),
        policy_revision: String::new(),
        installation_id: None,
        default_selected: false,
        review: AuthoredAgentReview {
            agent_name: String::new(),
            grants: Vec::new(),
            tool_tier_preferences: Vec::new(),
            verification_label: None,
            interactive_subagents: false,
            goal_skeptics_label: crate::agents::GoalSkepticsPolicy::Off
                .review_label()
                .to_string(),
            children: Vec::new(),
            sidecar: None,
            source: String::new(),
            trust_is_shared: true,
            trust_disclosure: crate::onboarding_agent::REVIEW_TRUST_DISCLOSURE.to_string(),
        },
    }
}
