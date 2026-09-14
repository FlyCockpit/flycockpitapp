//! Daemon apply/reconcile for authored agent packages.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use cockpit_db::db::authored_agent_packages::{
    AUTHORED_PACKAGE_SETTLEMENT_PENDING, AUTHORED_PACKAGE_SETTLEMENT_TERMINAL,
    AuthoredAgentPackageJournalRow, MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES,
};
use cockpit_proto::{
    AgentAuthoringProjection, ApplyAuthoredAgentPackageOutcome, ApplyAuthoredAgentPackageReceipt,
    ApplyAuthoredAgentPackageRequest, AuthoredAgentPackageReceiptQuery, AuthoredAgentReceiptStatus,
    AuthoredAgentRejectReason, AuthoredAgentReview, Response,
};
use sha2::{Digest, Sha256};

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
    let fence = publication_fence(&request, fence)?;
    if let Some(outcome) = replay_existing_journal(ctx, &request, &fence).await? {
        return Ok(outcome);
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
    if request.validate_only {
        return Ok(ApplyAuthoredAgentPackageOutcome::Review(package.review));
    }
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
    let sidecar_selection = crate::onboarding_agent::authored_sidecar_selection_config(
        &request.package.sidecars,
        &providers,
    )
    .context("resolving authored sidecar publication")?;
    let sidecar_intent_json =
        serde_json::to_string(&sidecar_selection).context("encoding authored sidecar intent")?;
    let package_files_json = encode_package_files(&package.files)?;
    let review_json =
        serde_json::to_string(&package.review).context("encoding authored package review")?;
    let intent = AuthoredAgentPackageJournalRow {
        owner_digest: fence.owner_digest.clone(),
        client_operation_id: request.client_operation_id.clone(),
        request_hash: fence.request_hash.to_vec(),
        fencing_generation: fence.fencing_generation,
        policy_revision: snapshot.policy_revision.clone(),
        package_digest: package.digest.clone(),
        draft_revision: package.digest.clone(),
        expected_draft_revision: request.package.draft_revision.clone(),
        agent_name: request.package.name.clone(),
        source_locator: request.package.source.source_locator.clone(),
        source_pin: request.package.source.pin.clone(),
        require_third_party,
        third_party_trust_confirmed: request.package.source.third_party_trust_confirmed,
        make_default: request.package.make_default,
        sidecar_intent_json,
        package_files_json,
        review_json,
        installation_id: None,
        default_selected: request.package.make_default,
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
        settlement_phase: AUTHORED_PACKAGE_SETTLEMENT_PENDING.to_string(),
        terminal_response_json: None,
        created_at_unix_ms: now,
    };
    let journal = ctx
        .db
        .begin_authored_agent_package_journal(intent)
        .await
        .context("recording authored package publication intent")?;
    complete_pending_authored_journal(ctx, journal).await
}

pub async fn recover_authored_agent_package_journals(ctx: &DaemonContext) -> Result<u64> {
    let rows = ctx.db.list_authored_agent_package_journals().await?;
    let mut recovered = 0_u64;
    for row in rows {
        if row.settlement_phase == AUTHORED_PACKAGE_SETTLEMENT_PENDING {
            complete_pending_authored_journal(ctx, row).await?;
            recovered = recovered.saturating_add(1);
            continue;
        }
        let Some(json) = row.terminal_response_json.as_deref() else {
            anyhow::bail!(
                "authored package journal {} is terminal without a receipt",
                row.client_operation_id
            );
        };
        if finish_matching_local_operation(ctx, &row, json).await? {
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
    if let Some(journal) = ctx
        .db
        .authored_agent_package_journal(owner.to_owned(), query.client_operation_id.clone())
        .await?
        && let Some(json) = journal.terminal_response_json.as_deref()
        && let Ok(Response::AuthoredAgentPackage(ApplyAuthoredAgentPackageOutcome::Receipt(
            receipt,
        ))) = serde_json::from_str(json)
    {
        return Ok(receipt);
    }
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
                && let Some(json) = journal.terminal_response_json.as_deref()
                && let Ok(Response::AuthoredAgentPackage(
                    ApplyAuthoredAgentPackageOutcome::Receipt(receipt),
                )) = serde_json::from_str(json)
            {
                return Ok(receipt);
            }
            Ok(unknown_receipt(&query.client_operation_id, None))
        }
        _ => Ok(unknown_receipt(&query.client_operation_id, None)),
    }
}

fn publication_fence(
    request: &ApplyAuthoredAgentPackageRequest,
    fence: Option<AuthoredApplyFence>,
) -> Result<AuthoredApplyFence> {
    if let Some(fence) = fence {
        return Ok(fence);
    }
    let encoded = serde_json::to_vec(request).context("encoding unfenced authored apply")?;
    let request_hash: [u8; 32] = Sha256::digest(&encoded).into();
    let owner_digest = request
        .onboarding
        .as_ref()
        .map(|row| format!("onboarding:{}", row.run_id))
        .unwrap_or_else(|| "authored-unfenced".to_string());
    Ok(AuthoredApplyFence {
        owner_digest,
        request_hash,
        fencing_generation: 1,
    })
}

async fn replay_existing_journal(
    ctx: &DaemonContext,
    request: &ApplyAuthoredAgentPackageRequest,
    fence: &AuthoredApplyFence,
) -> Result<Option<ApplyAuthoredAgentPackageOutcome>> {
    let Some(journal) = ctx
        .db
        .authored_agent_package_journal(
            fence.owner_digest.clone(),
            request.client_operation_id.clone(),
        )
        .await?
    else {
        return Ok(None);
    };
    ensure!(
        journal.request_hash.as_slice() == fence.request_hash.as_slice()
            && journal.fencing_generation == fence.fencing_generation,
        "authored package journal identity does not match the original request"
    );
    if journal.settlement_phase == AUTHORED_PACKAGE_SETTLEMENT_TERMINAL {
        if let Some(json) = journal.terminal_response_json.as_deref()
            && let Ok(Response::AuthoredAgentPackage(outcome)) = serde_json::from_str(json)
        {
            return Ok(Some(outcome));
        }
        bail_terminal_journal()?;
    }
    complete_pending_authored_journal(ctx, journal)
        .await
        .map(Some)
}

fn bail_terminal_journal() -> Result<Option<ApplyAuthoredAgentPackageOutcome>> {
    anyhow::bail!("authored package journal terminal receipt is not a package outcome")
}

async fn complete_pending_authored_journal(
    ctx: &DaemonContext,
    journal: AuthoredAgentPackageJournalRow,
) -> Result<ApplyAuthoredAgentPackageOutcome> {
    if journal.settlement_phase == AUTHORED_PACKAGE_SETTLEMENT_TERMINAL {
        if let Some(json) = journal.terminal_response_json.as_deref()
            && let Ok(Response::AuthoredAgentPackage(outcome)) = serde_json::from_str(json)
        {
            let _ = finish_matching_local_operation(ctx, &journal, json).await?;
            return Ok(outcome);
        }
        anyhow::bail!("authored package journal terminal receipt is not a package outcome");
    }
    let files = decode_package_files(&journal.package_files_json)?;
    let sidecar_selection: crate::config::image_sidecar::SidecarSelectionConfig =
        serde_json::from_str(&journal.sidecar_intent_json)
            .context("decoding authored sidecar intent")?;
    let review: AuthoredAgentReview =
        serde_json::from_str(&journal.review_json).context("decoding authored package review")?;
    let now = crate::workspace_lease::now_unix_ms();
    let service = ctx.agent_installation_service()?;
    let install = service
        .commit_authored_package(
            journal.client_operation_id.clone(),
            &journal.agent_name,
            journal.source_locator.clone(),
            journal.source_pin.clone(),
            journal.require_third_party,
            journal.third_party_trust_confirmed,
            files,
            journal.package_digest.clone(),
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
            anyhow::bail!("authored package installation failed: {}", error.message);
        }
        other => {
            anyhow::bail!("authored package installation did not complete: {other:?}");
        }
    };
    crate::onboarding_agent::publish_authored_sidecar_config(&sidecar_selection)
        .context("publishing authored sidecar selection")?;
    if journal.make_default
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
            journal.agent_name.clone(),
            journal.expected_draft_revision.clone(),
            journal.draft_revision.clone(),
            journal.package_digest.clone(),
            now,
        )
        .await
        .context("committing authored draft revision")?;
    if !cas_ok {
        return settle_authored_outcome(
            ctx,
            &journal,
            installation_id,
            ApplyAuthoredAgentPackageOutcome::Rejected {
                reason: AuthoredAgentRejectReason::StaleDraft,
                message: "authored draft revision does not match the last authoritative draft; edit/retry the current revision".into(),
                projection: None,
            },
        )
        .await;
    }
    let mut receipt = ApplyAuthoredAgentPackageReceipt {
        client_operation_id: journal.client_operation_id.clone(),
        receipt_id: uuid::Uuid::now_v7(),
        status: AuthoredAgentReceiptStatus::Committed,
        package_digest: journal.package_digest.clone(),
        policy_revision: journal.policy_revision.clone(),
        installation_id: installation_id.clone(),
        default_selected: journal.make_default,
        review,
    };
    if let Ok(id) = uuid::Uuid::parse_str(&operation_id) {
        receipt.receipt_id = id;
    }
    settle_authored_outcome(
        ctx,
        &journal,
        installation_id,
        ApplyAuthoredAgentPackageOutcome::Receipt(receipt),
    )
    .await
}

async fn settle_authored_outcome(
    ctx: &DaemonContext,
    journal: &AuthoredAgentPackageJournalRow,
    installation_id: Option<String>,
    outcome: ApplyAuthoredAgentPackageOutcome,
) -> Result<ApplyAuthoredAgentPackageOutcome> {
    let terminal_response_json =
        serde_json::to_string(&Response::AuthoredAgentPackage(outcome.clone()))
            .context("encoding authored package receipt")?;
    ctx.db
        .finish_authored_agent_package_journal(
            journal.owner_digest.clone(),
            journal.client_operation_id.clone(),
            installation_id,
            terminal_response_json.clone(),
        )
        .await
        .context("finishing authored package journal")?;
    let _ = finish_matching_local_operation(ctx, journal, &terminal_response_json).await?;
    Ok(outcome)
}

async fn finish_matching_local_operation(
    ctx: &DaemonContext,
    journal: &AuthoredAgentPackageJournalRow,
    terminal_response_json: &str,
) -> Result<bool> {
    let hash: [u8; 32] = journal
        .request_hash
        .as_slice()
        .try_into()
        .context("authored package journal request hash")?;
    match ctx
        .db
        .local_operation_settlement(
            journal.owner_digest.clone(),
            journal.client_operation_id.clone(),
        )
        .await?
    {
        Some(crate::db::local_operation_receipts::LocalOperationSettlement::Pending(_)) => {
            ctx.db
                .finish_local_operation(
                    journal.owner_digest.clone(),
                    journal.client_operation_id.clone(),
                    hash,
                    journal.fencing_generation,
                    "terminal_success".into(),
                    terminal_response_json.to_owned(),
                )
                .await
                .context("finishing authored package local operation from journal")?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn encode_package_files(files: &BTreeMap<String, Vec<u8>>) -> Result<String> {
    let raw_bytes: u64 = files
        .values()
        .map(|bytes| bytes.len() as u64)
        .fold(0_u64, u64::saturating_add);
    ensure!(
        raw_bytes <= crate::agents::MAX_PACKAGE_BYTES,
        "authored package files exceed the canonical package limit"
    );
    let encoded = files
        .iter()
        .map(|(path, bytes)| (path.clone(), crate::intel::hex_lower(bytes)))
        .collect::<BTreeMap<_, _>>();
    let json = serde_json::to_string(&encoded).context("encoding authored package files")?;
    ensure!(
        json.len() <= MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES,
        "authored package files exceed the durable intent limit"
    );
    Ok(json)
}

fn decode_package_files(json: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let encoded: BTreeMap<String, String> =
        serde_json::from_str(json).context("decoding authored package files")?;
    let mut files = BTreeMap::new();
    for (path, hex) in encoded {
        let bytes = decode_hex(&hex)
            .with_context(|| format!("authored package file `{path}` is not hex"))?;
        files.insert(path, bytes);
    }
    Ok(files)
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    ensure!(
        value.len() % 2 == 0,
        "hex encoding must contain an even number of digits"
    );
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars = value.as_bytes();
    for chunk in chars.chunks_exact(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn hex_digit(digit: u8) -> Result<u8> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => anyhow::bail!("invalid hex digit"),
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
            sidecars: Vec::new(),
            source: String::new(),
            trust_is_shared: true,
            trust_disclosure: crate::onboarding_agent::REVIEW_TRUST_DISCLOSURE.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{decode_package_files, encode_package_files};

    #[test]
    fn authored_package_intent_precedes_every_publication_effect() {
        let source = include_str!("agent_authoring.rs");
        let apply = source
            .split("pub async fn apply_package_under_publication_lock")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub async fn recover_authored_agent_package_journals")
                    .next()
            })
            .expect("apply under publication lock");
        let intent = apply
            .find("begin_authored_agent_package_journal")
            .expect("durable intent insert");
        let complete = apply
            .find("complete_pending_authored_journal")
            .expect("complete from intent");
        assert!(
            intent < complete,
            "authored publication must record durable intent before completing effects"
        );
        assert!(
            !apply.contains("commit_authored_package("),
            "effects must run only from complete_pending_authored_journal after intent"
        );
    }

    #[test]
    fn onboarding_and_rpc_apply_both_record_a_publication_fence() {
        let dispatch = include_str!("server/dispatch.rs");
        let onboarding = dispatch
            .split("apply_package_under_publication_lock")
            .nth(1)
            .expect("onboarding authored apply");
        assert!(
            onboarding.contains("AuthoredApplyFence"),
            "onboarding must journal authored publication under the owner fence"
        );
        assert!(
            !onboarding
                .lines()
                .take(20)
                .any(|line| line.trim() == "None,"),
            "onboarding must not skip the authored publication journal"
        );
    }

    #[test]
    fn onboarding_compensation_inverts_draft_cas_under_composite_journal_identity() {
        let dispatch = include_str!("server/dispatch.rs");
        let compensate = dispatch
            .split("async fn compensate_onboarding_agent_publication")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub(super) async fn recover_onboarding_agent_publication_journals")
                    .next()
            })
            .expect("onboarding compensation");
        assert!(
            compensate.contains("compensate_authored_agent_package_journal"),
            "onboarding compensation must invoke the composite authored-journal inverse"
        );
        assert!(
            compensate.contains("authored_owner_digest"),
            "onboarding compensation must pass the persisted authored owner, not a suffix-only operation id"
        );
        assert!(
            !compensate.contains("delete_authored_agent_package_journals_by_client_operation"),
            "compensation must not delete every journal sharing a client operation id"
        );
        let authored_idx = compensate
            .find("compensate_authored_agent_package_journal")
            .expect("authored inverse");
        let install_idx = compensate
            .find("cleanup_owned_onboarding_installation")
            .expect("installation inverse");
        assert!(
            authored_idx < install_idx,
            "authored inverse must run before other effects so recovery cannot complete-forward a compensating apply"
        );

        let recover = dispatch
            .split("pub(super) async fn recover_onboarding_agent_publication_journals")
            .nth(1)
            .and_then(|tail| tail.split("/// Recover the catalog").next())
            .expect("onboarding recovery");
        assert!(recover.contains("authored_owner_digest"));
        assert!(recover.contains("compensate_onboarding_agent_publication"));

        let apply = dispatch
            .split("if wizard_id == crate::wizard::ONBOARDING_AGENT_WIZARD_ID")
            .nth(1)
            .and_then(|tail| {
                tail.split("crate::wizard::apply_setup_wizard_answers_authoritative")
                    .next()
            })
            .expect("onboarding apply");
        assert!(
            apply.contains("authored_owner_digest"),
            "onboarding must persist the nested authored journal owner before effects"
        );
        assert!(
            apply.contains("journal_authored_owner = settlement_owner.clone()"),
            "the persisted owner must be the capability owner used as the authored fence"
        );
        assert!(
            !apply.contains("owned_installation_id = installation_id"),
            "compensation and settlement must keep the minted operation identity"
        );
        assert_eq!(
            apply
                .matches("compensate_onboarding_agent_publication")
                .count(),
            3,
            "every onboarding failure path compensates"
        );
        assert_eq!(
            apply.matches("settlement_owner.clone(),").count(),
            4,
            "the authored fence and every compensation call must pass the persisted capability owner"
        );
    }

    #[test]
    fn recovery_completes_pending_journals_without_rechecking_live_policy() {
        let source = include_str!("agent_authoring.rs");
        let recover = source
            .split("pub async fn recover_authored_agent_package_journals")
            .nth(1)
            .and_then(|tail| tail.split("pub async fn receipt").next())
            .expect("authored recovery");
        assert!(recover.contains("AUTHORED_PACKAGE_SETTLEMENT_PENDING"));
        assert!(recover.contains("complete_pending_authored_journal"));
        assert!(
            recover.contains("finish_matching_local_operation(ctx, &row, json)"),
            "already-terminal recovery must settle the matching local operation from the durable receipt"
        );
        let complete = source
            .split("async fn complete_pending_authored_journal")
            .nth(1)
            .and_then(|tail| {
                tail.split("async fn finish_matching_local_operation")
                    .next()
            })
            .expect("complete pending");
        assert!(complete.contains("commit_authored_package"));
        assert!(complete.contains("publish_authored_sidecar_config"));
        assert!(complete.contains("set_default_agent_installation"));
        assert!(complete.contains("cas_authored_agent_package_draft"));
        assert!(complete.contains("settle_authored_outcome"));
        assert!(!complete.contains("expected_policy_revision"));
        assert!(!complete.contains("PolicyRevisionConflict"));
        assert!(!complete.contains("onboarding_snapshot"));
    }

    #[test]
    fn complete_forward_settles_the_matching_local_operation_from_the_persisted_receipt() {
        let source = include_str!("agent_authoring.rs");
        let settle = source
            .split("async fn settle_authored_outcome")
            .nth(1)
            .and_then(|tail| {
                tail.split("async fn finish_matching_local_operation")
                    .next()
            })
            .expect("settle authored outcome");
        assert!(settle.contains("finish_authored_agent_package_journal"));
        assert!(
            settle
                .contains("finish_matching_local_operation(ctx, journal, &terminal_response_json)"),
            "complete-forward must settle the local operation from the JSON just persisted, not the pre-write journal snapshot"
        );
        assert!(
            !settle.contains("journal.terminal_response_json"),
            "the in-memory pending journal still has terminal_response_json: None"
        );
        let finish = source
            .split("async fn finish_matching_local_operation")
            .nth(1)
            .and_then(|tail| tail.split("fn encode_package_files").next())
            .expect("finish matching local operation");
        assert!(
            !finish.contains("journal.terminal_response_json"),
            "local-operation settlement must take the durable terminal payload as an argument"
        );
        assert!(finish.contains("terminal_response_json.to_owned()"));
    }

    #[test]
    fn apply_reuses_terminal_journal_for_duplicate_client_operation_id() {
        let source = include_str!("agent_authoring.rs");
        let apply = source
            .split("pub async fn apply_package_under_publication_lock")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub async fn recover_authored_agent_package_journals")
                    .next()
            })
            .expect("apply under publication lock");
        assert!(
            apply.contains("replay_existing_journal"),
            "duplicate create submits must query the durable receipt instead of minting a replacement operation"
        );
        assert!(
            apply.contains("AUTHORED_PACKAGE_SETTLEMENT_PENDING"),
            "pending journals must remain visible until the terminal receipt lands"
        );
    }

    #[test]
    fn receipt_query_never_mints_a_replacement_operation() {
        let source = include_str!("agent_authoring.rs");
        let receipt = source
            .split("pub async fn receipt")
            .nth(1)
            .and_then(|tail| tail.split("fn encode_package_files").next())
            .expect("receipt lookup");
        assert!(receipt.contains("authored_agent_package_journal"));
        assert!(!receipt.contains("begin_authored_agent_package_journal"));
    }

    #[test]
    fn editor_lease_and_onboarding_create_share_exact_operation_settlement() {
        let agent_management = include_str!("agent_management.rs");
        assert!(
            agent_management.contains("completion_operation_id"),
            "editor lease settlement must bind to one stable client operation id"
        );
        assert!(
            agent_management.contains("terminal_result_json"),
            "editor lease settlement must replay the durable terminal receipt"
        );
        let apply = include_str!("agent_authoring.rs");
        assert!(apply.contains("replay_existing_journal"));
        assert!(apply.contains("set_default_agent_installation"));
        assert!(apply.contains("finish_matching_local_operation"));
    }

    #[test]
    fn durable_intent_capacity_matches_hex_encoded_canonical_packages() {
        use cockpit_db::db::authored_agent_packages::{
            MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES, MAX_AUTHORED_PACKAGE_FILES_JSON_WRAP_BYTES,
            MAX_CANONICAL_AGENT_PACKAGE_BYTES,
        };
        assert_eq!(
            MAX_CANONICAL_AGENT_PACKAGE_BYTES,
            crate::agents::MAX_PACKAGE_BYTES as usize
        );
        assert_eq!(
            MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES,
            MAX_CANONICAL_AGENT_PACKAGE_BYTES
                .saturating_mul(2)
                .saturating_add(MAX_AUTHORED_PACKAGE_FILES_JSON_WRAP_BYTES)
        );
        assert!(
            include_str!("agent_installation.rs").contains(
                "const MAX_AGENT_PACKAGE_BYTES: usize = crate::agents::MAX_PACKAGE_BYTES as usize"
            ),
            "installation authority must share the canonical package byte cap"
        );
        let mut files = BTreeMap::new();
        files.insert("agent.md".into(), vec![b'x'; 512 * 1024]);
        let json = encode_package_files(&files)
            .expect("a 512 KiB canonical file must fit after hex encoding");
        assert!(
            json.len() > 1_048_576,
            "hex encoding of 512 KiB exceeds the former 1 MiB journal cap"
        );
        assert!(json.len() <= MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES);
        assert_eq!(decode_package_files(&json).unwrap(), files);

        let mut full = BTreeMap::new();
        full.insert(
            "agent.md".into(),
            vec![b'y'; crate::agents::MAX_PACKAGE_BYTES as usize],
        );
        let full_json = encode_package_files(&full)
            .expect("a canonical 4 MiB package must journal after hex encoding");
        assert!(full_json.len() <= MAX_AUTHORED_PACKAGE_FILES_JSON_BYTES);
        assert_eq!(decode_package_files(&full_json).unwrap(), full);

        let mut oversize = BTreeMap::new();
        oversize.insert(
            "agent.md".into(),
            vec![b'z'; crate::agents::MAX_PACKAGE_BYTES as usize + 1],
        );
        assert!(
            encode_package_files(&oversize).is_err(),
            "durable intent must not accept a package above the canonical tree cap"
        );
    }
}
