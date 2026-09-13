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

pub async fn apply_package(
    ctx: &DaemonContext,
    request: ApplyAuthoredAgentPackageRequest,
) -> Result<ApplyAuthoredAgentPackageOutcome> {
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
    let service = ctx.agent_installation_service()?;
    let now = crate::workspace_lease::now_unix_ms();
    let install = service
        .commit_authored_package(
            request.client_operation_id.clone(),
            &request.package.name,
            request.package.source.source_locator.clone(),
            request.package.source.pin.clone(),
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
    let mut receipt = crate::onboarding_agent::committed_receipt(
        request.client_operation_id,
        &package,
        &snapshot,
        installation_id,
        default_selected,
    );
    if let Ok(id) = uuid::Uuid::parse_str(&operation_id) {
        receipt.receipt_id = id;
    }
    Ok(ApplyAuthoredAgentPackageOutcome::Receipt(receipt))
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
