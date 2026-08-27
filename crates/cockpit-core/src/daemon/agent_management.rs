//! Daemon-owned agent discovery and mutation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::computer::frame::hex;
use crate::daemon::proto::{
    AgentEditSnapshot, AgentEditTarget, AgentEditorCompletion, AgentEditorLease,
    AgentEditorSettlementStatus, AgentEntryKind, AgentInventoryEntry, AgentMutation,
    AgentMutationResult, AgentSourceLayer, ErrorCode, ErrorPayload, Response,
};
use crate::daemon::server::DaemonContext;

const EDITOR_LEASE_TTL: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedEditorReplay {
    owner_digest: String,
    snapshot: AgentEditSnapshot,
}

impl zeroize::Zeroize for SealedEditorReplay {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.owner_digest);
        zeroize::Zeroize::zeroize(&mut self.snapshot.name);
        zeroize::Zeroize::zeroize(&mut self.snapshot.markdown);
        zeroize::Zeroize::zeroize(&mut self.snapshot.canonical_preview);
        zeroize::Zeroize::zeroize(&mut self.snapshot.source_identity);
        zeroize::Zeroize::zeroize(&mut self.snapshot.revision);
        zeroize::Zeroize::zeroize(&mut self.snapshot.goal_supervision_json);
        zeroize::Zeroize::zeroize(&mut self.snapshot.projection_digest);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedEditorCompletion {
    owner_digest: String,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    markdown: Option<String>,
}

/// Borrowed encoding view used so sealing a submitted document does not
/// allocate ordinary `String` copies of any payload field.
#[derive(serde::Serialize)]
struct SealedEditorCompletionRef<'a> {
    owner_digest: &'a str,
    client_operation_id: &'a str,
    project_root: &'a str,
    lease_id: &'a str,
    markdown: Option<&'a str>,
}

enum EditorPublicationAttempt {
    Published(Response),
    Rejected(ErrorPayload),
    Pending(ErrorPayload),
}

impl zeroize::Zeroize for SealedEditorCompletion {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.owner_digest);
        zeroize::Zeroize::zeroize(&mut self.client_operation_id);
        zeroize::Zeroize::zeroize(&mut self.project_root);
        zeroize::Zeroize::zeroize(&mut self.lease_id);
        zeroize::Zeroize::zeroize(&mut self.markdown);
    }
}

fn editor_replay_handle(lease_id: &str) -> String {
    format!("agent-editor-lease:{lease_id}")
}

fn editor_completion_handle(completion_identity: [u8; 32]) -> String {
    format!(
        "agent-editor-completion:{}",
        hex::encode(completion_identity)
    )
}

fn load_editor_completion_sync(
    vault: &crate::secure_key::SecretVault,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<zeroize::Zeroizing<SealedEditorCompletion>, ErrorPayload> {
    let operation_id = row
        .completion_operation_id
        .as_deref()
        .ok_or_else(|| internal("completing editor lease omitted its operation id"))?;
    let expected_handle = editor_completion_handle(
        row.completion_identity
            .ok_or_else(|| internal("completing editor lease omitted its identity"))?,
    );
    let handle = row
        .completion_handle
        .as_deref()
        .ok_or_else(|| internal("completing editor lease omitted its sealed payload"))?;
    if handle != expected_handle {
        return Err(internal("editor completion payload handle is corrupt"));
    }
    let plaintext = vault
        .get_item(
            cockpit_db::secret_vault::SecretVaultKind::SealedState,
            handle,
        )
        .map_err(internal)?;
    // Wrap immediately so every subsequent binding/identity validation error
    // zeroizes the recovered completion document before returning.
    let payload = zeroize::Zeroizing::new(
        serde_json::from_slice::<SealedEditorCompletion>(plaintext.as_slice()).map_err(internal)?,
    );
    if payload.owner_digest != row.owner_digest
        || payload.client_operation_id != operation_id
        || payload.project_root != row.project_root
        || payload.lease_id != row.lease_id
    {
        return Err(internal(
            "editor completion sealed payload binding mismatch",
        ));
    }
    let identity_plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(&(
            "complete_agent_editor_lease",
            &payload.client_operation_id,
            &payload.project_root,
            &payload.lease_id,
            payload.markdown.as_deref(),
        ))
        .map_err(internal)?,
    );
    let identity = vault.keyed_identity(
        b"flycockpit.agent-editor.completion.v2",
        identity_plaintext.as_slice(),
    );
    if row.completion_identity != Some(identity) {
        return Err(internal(
            "editor completion sealed payload identity mismatch",
        ));
    }
    Ok(payload)
}

async fn load_editor_completion(
    ctx: &DaemonContext,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<zeroize::Zeroizing<SealedEditorCompletion>, ErrorPayload> {
    let vault = ctx.secret_vault.clone();
    let row = row.clone();
    tokio::task::spawn_blocking(move || load_editor_completion_sync(&vault, &row))
        .await
        .map_err(join_error)?
}

fn load_editor_replay_sync(
    vault: &crate::secure_key::SecretVault,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<AgentEditSnapshot, ErrorPayload> {
    let expected_handle = editor_replay_handle(&row.lease_id);
    let handle = row
        .snapshot_handle
        .as_deref()
        .ok_or_else(|| internal("active editor lease omitted its sealed replay handle"))?;
    if handle != expected_handle {
        return Err(internal("editor lease replay handle is corrupt"));
    }
    let plaintext = vault
        .get_item(
            cockpit_db::secret_vault::SecretVaultKind::SealedState,
            handle,
        )
        .map_err(internal)?;
    let identity =
        vault.keyed_identity(b"flycockpit.agent-editor.snapshot.v1", plaintext.as_slice());
    if identity != row.snapshot_identity {
        return Err(internal("editor lease sealed replay identity mismatch"));
    }
    let replay = zeroize::Zeroizing::new(
        serde_json::from_slice::<SealedEditorReplay>(plaintext.as_slice()).map_err(internal)?,
    );
    if replay.owner_digest != row.owner_digest {
        return Err(internal("editor lease sealed replay owner mismatch"));
    }
    Ok(replay.snapshot.clone())
}

async fn load_editor_replay(
    ctx: &DaemonContext,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<AgentEditSnapshot, ErrorPayload> {
    let vault = ctx.secret_vault.clone();
    let row = row.clone();
    tokio::task::spawn_blocking(move || load_editor_replay_sync(&vault, &row))
        .await
        .map_err(join_error)?
}

async fn delete_editor_replay_and_row(
    ctx: &DaemonContext,
    row: crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<(), ErrorPayload> {
    let vault = ctx.secret_vault.clone();
    let handle = row
        .snapshot_handle
        .unwrap_or_else(|| editor_replay_handle(&row.lease_id));
    let lease_id = row.lease_id;
    ctx.db
        .transaction(move |conn| {
            let deleted = conn.execute(
                "DELETE FROM agent_editor_leases WHERE lease_id=?1 AND state='open' AND expires_at_unix_ms < ?2",
                rusqlite::params![&lease_id, chrono::Utc::now().timestamp_millis()],
            )?;
            if deleted == 0 {
                return Ok(());
            }
            vault
                .delete_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &handle,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            Ok(())
        })
        .await
        .map_err(internal)
}

/// Finish a completion for which the filesystem publication revision is
/// already durable.  Recovery must not depend on the short-lived sealed
/// markdown after this point: the journal row itself is sufficient evidence
/// for an exact, target-bound Saved receipt.
async fn settle_published_editor_completion(
    ctx: &DaemonContext,
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
) -> Result<Response, ErrorPayload> {
    if row.owner_digest.trim().is_empty() {
        return Err(internal("published editor completion omitted its owner"));
    }
    let completion_identity = row
        .completion_identity
        .ok_or_else(|| internal("published editor completion omitted its identity"))?;
    let completion_handle = row
        .completion_handle
        .clone()
        .ok_or_else(|| internal("published editor completion omitted its sealed payload handle"))?;
    if completion_handle != editor_completion_handle(completion_identity) {
        return Err(internal(
            "published editor completion payload handle is corrupt",
        ));
    }
    let operation_id = row
        .completion_operation_id
        .as_deref()
        .ok_or_else(|| internal("published editor completion omitted its operation id"))?;
    let result_revision = row
        .publication_result_revision
        .clone()
        .ok_or_else(|| internal("published editor completion omitted its result revision"))?;
    if row.publication_phase != "published" {
        return Err(internal(
            "editor completion revision exists without published phase",
        ));
    }

    let consumed_config_generation = row
        .consumed_config_generation
        .ok_or_else(|| internal("published editor completion omitted its consumed generation"))?;
    let result_config_generation = row
        .result_config_generation
        .ok_or_else(|| internal("published editor completion omitted its result generation"))?;
    // The journal allocates the exact generation before publication. Recovery
    // only raises the process-local floor to that durable value; it never
    // allocates a second generation for the same filesystem commit.
    crate::daemon::server::inventory::publish_committed_config_generation_at_least(
        result_config_generation,
    );
    let receipt = editor_completion(
        row,
        operation_id,
        &row.project_root,
        AgentEditorSettlementStatus::Saved {
            result_revision,
            outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
        },
    );
    let json = serde_json::to_string(&receipt).map_err(internal)?;
    let vault = ctx.secret_vault.clone();
    let lease_id = row.lease_id.clone();
    let operation_id = operation_id.to_owned();
    ctx.db
        .transaction(move |conn| {
            // Terminal metadata and secret cleanup share the same writer
            // transaction. Deletion is idempotent and deliberately does not
            // decrypt the payload, so corrupt ciphertext cannot orphan a
            // forever-live completion handle.
            vault
                .delete_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &completion_handle,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            crate::db::agent_editor_leases::finish_agent_editor_completion_conn(
                conn,
                &lease_id,
                completion_identity,
                &operation_id,
                &json,
                consumed_config_generation,
                result_config_generation,
            )
        })
        .await
        .map_err(internal)?;
    Ok(Response::AgentEditorLeaseCompleted(receipt))
}

/// Boot/periodic maintenance for abandoned editor authority. Expired open
/// leases and their sealed payloads disappear atomically. Completing claims
/// remain durable across restart: after the bounded claim interval, the exact
/// operation may resubmit its original content and reconcile the filesystem.
pub(crate) async fn maintain_editor_leases(ctx: &DaemonContext) -> Result<(), ErrorPayload> {
    let expired = ctx
        .db
        .expired_open_agent_editor_leases(chrono::Utc::now().timestamp_millis())
        .await
        .map_err(internal)?;
    for row in expired {
        delete_editor_replay_and_row(ctx, row).await?;
    }
    let stale_before = chrono::Utc::now()
        .timestamp_millis()
        .saturating_sub(crate::db::agent_editor_leases::AGENT_EDITOR_COMPLETION_CLAIM_MS);
    let completing = ctx
        .db
        .recoverable_agent_editor_completions(stale_before)
        .await
        .map_err(internal)?;
    for row in completing {
        if row.publication_result_revision.is_some() {
            if let Err(error) = settle_published_editor_completion(ctx, &row).await {
                tracing::warn!(
                    error = %error.message,
                    lease_id = row.lease_id,
                    "published editor completion metadata could not be terminalized"
                );
            }
            continue;
        }
        let mut payload = match load_editor_completion(ctx, &row).await {
            Ok(payload) => payload,
            Err(error) => {
                // A single damaged or unavailable sealed completion remains
                // inspectable; it must not permanently suppress the daemon
                // socket needed to diagnose and settle other work.
                tracing::warn!(
                    error = %error.message,
                    lease_id = row.lease_id,
                    "editor completion recovery evidence is unavailable"
                );
                continue;
            }
        };
        let client_operation_id = std::mem::take(&mut payload.client_operation_id);
        let project_root = std::mem::take(&mut payload.project_root);
        let lease_id = std::mem::take(&mut payload.lease_id);
        let markdown = std::mem::take(&mut payload.markdown);
        let owner_digest = std::mem::take(&mut payload.owner_digest);
        if let Err(error) = complete_editor_lease(
            ctx,
            client_operation_id,
            project_root,
            lease_id,
            markdown.map(cockpit_proto::SensitiveWirePayload::new),
            owner_digest,
        )
        .await
        {
            tracing::warn!(
                error = %error.message,
                lease_id = row.lease_id,
                "editor completion remains pending after maintenance"
            );
        }
    }
    Ok(())
}

/// The singleton daemon may reclaim every incomplete editor completion during
/// pre-socket boot: no live predecessor can still own the in-memory claim.
pub(crate) async fn recover_editor_leases_before_publish(
    ctx: &DaemonContext,
    publication: crate::daemon::config_publication_recovery::PreSocketConfigPublication,
) -> Result<(), ErrorPayload> {
    let config_lock_deadline = publication.deadline();
    let completing = ctx
        .db
        .recoverable_agent_editor_completions(chrono::Utc::now().timestamp_millis())
        .await
        .map_err(internal)?;
    for row in completing {
        if row.publication_result_revision.is_some() {
            if let Err(error) = settle_published_editor_completion(ctx, &row).await {
                tracing::warn!(
                    error = %error.message,
                    lease_id = row.lease_id,
                    "published editor completion metadata could not be terminalized before socket publication"
                );
            }
            continue;
        }
        let mut payload = match load_editor_completion(ctx, &row).await {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    error = %error.message,
                    lease_id = row.lease_id,
                    "editor completion recovery evidence is unavailable before socket publication"
                );
                continue;
            }
        };
        let client_operation_id = std::mem::take(&mut payload.client_operation_id);
        let project_root = std::mem::take(&mut payload.project_root);
        let lease_id = std::mem::take(&mut payload.lease_id);
        let markdown = std::mem::take(&mut payload.markdown);
        let owner_digest = std::mem::take(&mut payload.owner_digest);
        let response = match complete_editor_lease_inner(
            ctx,
            client_operation_id,
            project_root,
            lease_id,
            markdown.map(zeroize::Zeroizing::new),
            owner_digest,
            true,
            Some(config_lock_deadline),
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    error = %error.message,
                    lease_id = row.lease_id,
                    "editor completion could not be reconciled before socket publication"
                );
                continue;
            }
        };
        if matches!(
            response,
            Response::AgentEditorLeaseCompleted(AgentEditorCompletion {
                status: AgentEditorSettlementStatus::Pending,
                ..
            })
        ) {
            // Genuine ambiguity retains its sealed evidence and remains
            // queryable through the read-only settlement RPC. It must not
            // suppress the socket that clients need in order to inspect and
            // repair that state.
            tracing::warn!(
                lease_id = row.lease_id,
                "editor completion remains settlement-unknown after boot recovery"
            );
        }
    }
    Ok(())
}

pub async fn inventory(
    ctx: &DaemonContext,
    project_root: String,
) -> Result<Response, ErrorPayload> {
    let _publication = crate::daemon::server::inventory::read_authority_publication().await;
    let requested_project_root = project_root.clone();
    let root = trusted_root(ctx, &project_root).await?;
    maintain_editor_leases(ctx).await?;
    let expected_config_generation = crate::daemon::server::inventory::current_config_generation();
    tokio::task::spawn_blocking(move || {
        let guard =
            cockpit_config::config::hold_config_mutation_lock(&root.join(".cockpit/config.json"))
                .map_err(internal)?;
        inventory_sync(
            &root,
            &requested_project_root,
            expected_config_generation,
            &guard,
        )
    })
    .await
    .map_err(join_error)?
}

pub async fn edit_snapshot(
    ctx: &DaemonContext,
    project_root: String,
    name: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    tokio::task::spawn_blocking(move || {
        let guard =
            cockpit_config::config::hold_config_mutation_lock(&root.join(".cockpit/config.json"))
                .map_err(internal)?;
        recover_reset_all_locked(&root, &guard)?;
        snapshot_sync(&root, &name).map(Response::AgentEditSnapshot)
    })
    .await
    .map_err(join_error)?
}

pub async fn mutate(
    ctx: &DaemonContext,
    owner_digest: String,
    client_operation_id: String,
    mutation_intent_hash: String,
    request_hash: [u8; 32],
    fencing_generation: i64,
    project_root: String,
    mutation: AgentMutation,
    expected_revision: Option<String>,
) -> Result<Response, ErrorPayload> {
    let _publication = crate::daemon::server::inventory::write_authority_publication().await;
    let request_project_root = project_root.clone();
    let root = trusted_root(ctx, &project_root).await?;
    let canonical_root = root.to_string_lossy().into_owned();
    if let AgentMutation::AddMcpServer { name, .. } = &mutation
        && ctx
            .db
            .has_unsettled_agent_editor_lease(
                canonical_root.clone(),
                name.clone(),
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?
    {
        return Err(conflict(format!(
            "agent `{name}` is being edited; complete or cancel the editor lease before changing MCP bindings"
        )));
    }
    let keyed_request_identity = agent_mutation_keyed_identity(
        ctx,
        &owner_digest,
        &client_operation_id,
        &canonical_root,
        &request_project_root,
        &mutation_intent_hash,
    )?;
    let authority_db = ctx.db.clone();
    let authority_root = root.clone();
    let authority_mutation = mutation.clone();
    let authority_revision = expected_revision.clone();
    let journal_owner = owner_digest.clone();
    let journal_operation = client_operation_id.clone();
    let journal_root = canonical_root.clone();
    let journal_request_root = request_project_root.clone();
    let journal_intent_hash = mutation_intent_hash.clone();
    let publication_vault = ctx.secret_vault.clone();
    let (plan, result, committed_match, staged_mutations) = tokio::task::spawn_blocking(move || {
        let guard = cockpit_config::config::hold_config_mutation_lock(
            &authority_root.join(".cockpit/config.json"),
        )
        .map_err(internal)?;
        recover_reset_all_locked(&authority_root, &guard)?;
        #[cfg(target_os = "windows")]
        if let AgentMutation::AddMcpServer { name, .. } = &authority_mutation {
            recover_windows_agent_package_swap(&authority_root, name)?;
        }
        let plan = prepare_mutation_plan_sync(
            &authority_root,
            &authority_mutation,
            authority_revision.as_deref(),
            &publication_vault,
        )?;
        let credential_stage = match &authority_mutation {
            AgentMutation::AddMcpServer {
                server,
                server_json,
                profile,
                secret_values,
                ..
            } => Some((
                server.clone(),
                server_json.clone(),
                profile.clone(),
                secret_values.clone(),
            )),
            _ => None,
        };
        let journal_action = plan.action.clone();
        let journal_name = plan.agent_name.clone();
        let journal_revision = authority_revision.clone();
        let journal_identity = plan.intended_projection_identity.clone();
        let journal_consumed_identity = plan.consumed_projection_identity.clone();
        let affected_hint = i64::from(plan.affected_hint);
        let consumed_config_generation = i64::try_from(plan.consumed_config_generation)
            .map_err(|_| internal("agent mutation config generation is out of range"))?;
        let stage_vault = publication_vault.clone();
        let stage_root = journal_root.clone();
        let staged_mutations = authority_db
            .insert_agent_mutation_journal_under_publication_lock_with(
                crate::db::agent_mutation_journals::AgentMutationJournalFence {
                    owner_digest: journal_owner,
                    client_operation_id: journal_operation,
                    request_hash,
                    keyed_request_identity,
                    fencing_generation,
                    project_root: journal_root,
                    request_project_root: journal_request_root,
                    agent_name: journal_name,
                    action: journal_action,
                    consumed_revision: journal_revision,
                    affected_hint,
                    changed_hint: plan.changed_hint,
                    consumed_config_generation,
                    mutation_intent_hash: journal_intent_hash,
                    consumed_projection_identity: journal_consumed_identity,
                    intended_projection_identity: journal_identity,
                    created_at_unix_ms: chrono::Utc::now().timestamp_millis(),
                },
                move |conn| {
                    let Some((server_name, server_json, profile, staged)) = credential_stage else {
                        return Ok((std::collections::BTreeMap::new(), "{}".to_string()));
                    };
                    let server: crate::mcp::config::ServerConfig = serde_json::from_str(&server_json)?;
                    let mut config = crate::mcp::config::McpConfig::default();
                    config.servers.insert(server_name.clone(), server);
                    crate::daemon::server::validate_and_normalize_mcp_credentials(
                        &mut config,
                        &staged,
                    )
                    .map_err(|error| anyhow::anyhow!(error.message))?;
                    let server = &config.servers[&server_name];
                    let oauth_key = matches!(
                        server.auth_for_profile_named(&server_name, &profile)?,
                        crate::mcp::config::Auth::Oauth(_)
                    )
                    .then(|| crate::mcp::auth::cred_key_for(&server_name, &profile));
                    let mut mutations = std::collections::BTreeMap::new();
                    for reference in crate::mcp::auth::named_secret_references_for(
                        &server_name,
                        server,
                        &profile,
                    ) {
                        if let Some(value) = staged.get(&reference) {
                            crate::secret_ownership::reject_conflicting_named_ownership_on_conn(
                                conn,
                                &reference,
                                "mcp",
                                &stage_root,
                            )?;
                            let mutation = stage_vault.mutate_item_on_conn(
                                conn,
                                cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                                &reference,
                                Some(value.as_str().as_bytes()),
                            )?;
                            let ownership_inserted = conn.execute(
                                "INSERT OR IGNORE INTO secret_named_ownership
                                 (item_id, owner_kind, project_root, created_at)
                                 VALUES (?1, 'mcp', ?2, ?3)",
                                rusqlite::params![reference, stage_root, chrono::Utc::now().timestamp_millis()],
                            )? == 1;
                            mutations.insert(
                                reference.clone(),
                                AgentCredentialMutation {
                                    vault: mutation,
                                    ownership_inserted,
                                },
                            );
                        } else if oauth_key.as_deref() != Some(reference.as_str()) {
                            crate::secret_ownership::ensure_static_named_reference_owned_on_conn(
                                conn,
                                &stage_vault,
                                &reference,
                                "mcp",
                                &stage_root,
                            )?;
                        }
                    }
                    let compensation_json = serde_json::to_string(&mutations)?;
                    Ok((mutations, compensation_json))
                },
            )
            .map_err(|error| conflict(error.to_string()))?;
        // The same exclusive publication guard covers planning, durable fence
        // insertion, and atomic filesystem mutation. Consequently matching
        // bytes observed here cannot have been published by an intervening
        // agent writer and accidentally attributed to this operation.
        let result = mutate_sync_locked(
            &authority_root,
            authority_mutation,
            authority_revision,
            &guard,
            None,
        );
        let committed_match = result
            .as_ref()
            .err()
            .map(|_| projection_matches_plan(&authority_root, &plan, &publication_vault));
        Ok::<_, ErrorPayload>((plan, result, committed_match, staged_mutations))
    })
    .await
    .map_err(join_error)??;
    let mut response = match result {
        Ok(Response::AgentMutated(mut result)) => {
            bind_agent_mutation_receipt(
                &mut result,
                &client_operation_id,
                &mutation_intent_hash,
                &canonical_root,
                &request_project_root,
                &mutation,
            );
            Response::AgentMutated(result)
        }
        Ok(other) => other,
        Err(error) => {
            let committed_match = match committed_match {
                Some(Ok(matched)) => matched,
                Some(Err(read_error)) => {
                    tracing::warn!(
                        error = %read_error.message,
                        client_operation_id,
                        "agent mutation publication settlement is unreadable"
                    );
                    return Err(ErrorPayload {
                        code: ErrorCode::Shutdown,
                        message: "agent mutation settlement is unknown; retry the exact operation or query its status".into(),
                    });
                }
                None => false,
            };
            if !committed_match {
                compensate_agent_mcp_credentials(ctx, &canonical_root, &staged_mutations).await?;
                delete_agent_mutation_journal(ctx, &owner_digest, &client_operation_id).await?;
                return Err(error);
            }
            let projection_root = root.clone();
            let projection_name = plan.agent_name.clone();
            let result_is_absent = plan.result_is_absent;
            let (definition_revision, inventory_revision) =
                tokio::task::spawn_blocking(move || {
                    let revision = match projection_name.as_deref() {
                        Some(name) if !result_is_absent => {
                            current_definition_revision_sync(&projection_root, name).ok()
                        }
                        _ => None,
                    };
                    let inventory = if projection_name.is_none() {
                        current_inventory_revision(&projection_root).ok()
                    } else {
                        None
                    };
                    (revision, inventory)
                })
                .await
                .map_err(join_error)?;
            let result_revision = definition_revision
                .or_else(|| inventory_revision.clone())
                .unwrap_or_else(|| {
                    mutation_tombstone_revision(
                        &canonical_root,
                        cockpit_proto::agent_mutation_name(&mutation),
                        &plan.intended_projection_identity,
                    )
                });
            let result_config_generation = if plan.changed_hint {
                crate::daemon::server::inventory::publish_committed_config_generation()
            } else {
                crate::daemon::server::inventory::current_config_generation()
            };
            Response::AgentMutated(AgentMutationResult {
                client_operation_id: client_operation_id.clone(),
                mutation_intent_hash: mutation_intent_hash.clone(),
                project_root: canonical_root.clone(),
                requested_project_root: request_project_root.clone(),
                owner_scope: format!("project:{canonical_root}"),
                agent_name: plan.agent_name.clone(),
                changed: plan.changed_hint,
                affected: plan.affected_hint,
                snapshot: None,
                config_generation: result_config_generation,
                consumed_config_generation: plan.consumed_config_generation,
                result_config_generation,
                inventory_revision,
                consumed_revision: expected_revision.clone(),
                result_revision,
                completed_lease_id: None,
                outcome: cockpit_proto::AgentMutationOutcome::CommittedRefreshNeeded {
                    warning: "agent files were committed, but their refreshed projection is unavailable; reload agent settings to reconcile".into(),
                },
            })
        }
    };
    if matches!(
        &mutation,
        AgentMutation::AddMcpServer { secret_values, .. } if !secret_values.is_empty()
    ) && let Err(error) = ctx.publish_owner_redaction_table()
    {
        ctx.poison_redaction_publication(&error);
        return Err(ErrorPayload {
            code: ErrorCode::Shutdown,
            message: "agent MCP credentials were committed but redaction publication failed; restart the daemon and retry the exact operation".into(),
        });
    }
    if let Response::AgentMutated(result) = &mut response {
        bind_agent_mutation_receipt(
            result,
            &client_operation_id,
            &mutation_intent_hash,
            &canonical_root,
            &request_project_root,
            &mutation,
        );
    }
    // The live caller may receive a render snapshot, but the durable receipt
    // is metadata-only. Move (never clone) the snapshot out while encoding the
    // receipt, then restore it for the immediate response.
    let detached_snapshot = match &mut response {
        Response::AgentMutated(result) => result.snapshot.take(),
        _ => None,
    };
    let settlement = settle_agent_mutation_journal(
        ctx,
        owner_digest,
        client_operation_id,
        request_hash,
        fencing_generation,
        &response,
    )
    .await;
    if let Response::AgentMutated(result) = &mut response {
        result.snapshot = detached_snapshot;
    }
    settlement?;
    Ok(response)
}

#[derive(Clone)]
struct AgentMutationPlan {
    action: String,
    agent_name: Option<String>,
    intended_projection_identity: String,
    consumed_projection_identity: String,
    affected_hint: u32,
    changed_hint: bool,
    consumed_config_generation: u64,
    result_is_absent: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct AgentCredentialMutation {
    vault: crate::secure_key::SecretVaultMutation,
    ownership_inserted: bool,
}

fn projection_identity(vault: &crate::secure_key::SecretVault, bytes: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    match bytes {
        Some(bytes) => {
            hasher.update(b"flycockpit.agent-projection.present.v1\0");
            hasher.update(bytes);
        }
        None => hasher.update(b"flycockpit.agent-projection.absent.v1"),
    }
    let material = hasher.finalize();
    hex::encode(
        vault.keyed_request_identity(b"flycockpit.agent.projection.v1", material.as_slice()),
    )
}

fn agent_mutation_keyed_identity(
    ctx: &DaemonContext,
    owner: &str,
    operation: &str,
    canonical_root: &str,
    requested_root: &str,
    intent_hash: &str,
) -> Result<[u8; 32], ErrorPayload> {
    let encoded = zeroize::Zeroizing::new(
        serde_json::to_vec(&(
            owner,
            operation,
            canonical_root,
            requested_root,
            intent_hash,
        ))
        .map_err(internal)?,
    );
    Ok(ctx
        .secret_vault
        .keyed_request_identity(b"flycockpit.agent-mutation.request.v1", encoded.as_slice()))
}

fn prepare_mutation_plan_sync(
    root: &Path,
    mutation: &AgentMutation,
    expected_revision: Option<&str>,
    vault: &crate::secure_key::SecretVault,
) -> Result<AgentMutationPlan, ErrorPayload> {
    let (action, name, consumed, intended, affected_hint, absent) = match mutation {
        AgentMutation::EjectBuiltin { name } => {
            validate_name(name)?;
            if !crate::agents::is_builtin_agent(name) {
                return Err(bad_request("only a built-in agent can be ejected"));
            }
            let current = snapshot_sync(root, name)?;
            ensure_revision(&current.revision, expected_revision)?;
            ensure_workspace_source_or_embedded(&current)?;
            let consumed = target_projection_identity(root, name, vault)?;
            let intended = if nofollow_read(&project_agent_write_path(root, name)?)?.is_some() {
                // An existing package root is already the workspace override.
                // Eject is a no-op, so its journal projection must also be the
                // exact consumed projection rather than a flat-file payload.
                consumed.clone()
            } else {
                projection_identity(vault, Some(current.markdown.as_bytes()))
            };
            (
                "eject_builtin",
                Some(name.clone()),
                consumed,
                intended,
                1,
                false,
            )
        }
        AgentMutation::SaveDefinition { name, markdown }
        | AgentMutation::CreateDefinition { name, markdown } => {
            validate_name(name)?;
            let parsed = crate::agents::parse_agent(
                markdown,
                name,
                PathBuf::from("<daemon-agent-mutation-plan>"),
            )
            .map_err(bad_config)?;
            crate::agents::validate_invariants(&parsed).map_err(bad_config)?;
            if matches!(mutation, AgentMutation::SaveDefinition { .. }) {
                let current = snapshot_sync(root, name)?;
                ensure_revision(&current.revision, expected_revision)?;
                if !matches!(
                    current.source_layer,
                    AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
                ) {
                    return Err(conflict(
                        "save refused: another configuration layer owns this agent",
                    ));
                }
            } else if expected_revision.is_some() {
                return Err(bad_request("create cannot consume a document revision"));
            } else if crate::agents::resolve(root, name)
                .map_err(bad_config)?
                .is_some()
                || current_definition_bytes(root, name)?.is_some()
            {
                return Err(conflict(
                    "agent name already resolves in a configuration layer",
                ));
            }
            let action = if matches!(mutation, AgentMutation::SaveDefinition { .. }) {
                "save_definition"
            } else {
                "create_definition"
            };
            (
                action,
                Some(name.clone()),
                target_projection_identity(root, name, vault)?,
                projection_identity(
                    vault,
                    Some(&intended_definition_bytes(root, name, markdown)?),
                ),
                1,
                false,
            )
        }
        AgentMutation::DeleteCustom { name } => {
            validate_name(name)?;
            if crate::agents::is_builtin_agent(name) {
                return Err(bad_request("built-in agents cannot be deleted"));
            }
            let current = snapshot_sync(root, name)?;
            ensure_revision(&current.revision, expected_revision)?;
            if current.source_layer != AgentSourceLayer::Workspace
                || (!project_agent_path(root, name)?.is_file()
                    && !project_agent_path(root, name)?
                        .with_file_name(name)
                        .join("agent.md")
                        .is_file())
            {
                return Err(conflict("custom agent is not owned by the workspace layer"));
            }
            (
                "delete_custom",
                Some(name.clone()),
                target_projection_identity(root, name, vault)?,
                projection_identity(vault, None),
                1,
                true,
            )
        }
        AgentMutation::ResetBuiltin { name } => {
            validate_name(name)?;
            if !crate::agents::is_builtin_agent(name) {
                return Err(bad_request("only a built-in agent can be reset"));
            }
            let current = snapshot_sync(root, name)?;
            ensure_revision(&current.revision, expected_revision)?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict(
                    "built-in override is not owned by the workspace layer",
                ));
            }
            (
                "reset_builtin",
                Some(name.clone()),
                target_projection_identity(root, name, vault)?,
                projection_identity(vault, None),
                1,
                true,
            )
        }
        AgentMutation::ResetAllBuiltins => {
            let current = current_inventory_revision(root)?;
            ensure_revision(&current, expected_revision)?;
            let mut affected = 0_usize;
            for name in crate::agents::BUILTIN_AGENT_NAMES.iter().copied() {
                let flat = project_agent_path(root, name)?;
                if nofollow_read(&flat)?.is_some() || owned_package_dir(&flat, name)?.is_some() {
                    affected = affected.saturating_add(1);
                }
            }
            let affected = affected.try_into().unwrap_or(u32::MAX);
            (
                "reset_all_builtins",
                None,
                reset_all_target_projection_identity(root, vault)?,
                reset_all_projection_identity(vault),
                affected,
                true,
            )
        }
        AgentMutation::SavePackageMcp { name, mcp_json } => {
            validate_name(name)?;
            let current = snapshot_sync(root, name)?;
            ensure_revision(&current.revision, expected_revision)?;
            let _ = mcp_json;
            (
                "save_package_mcp",
                Some(name.clone()),
                target_projection_identity(root, name, vault)?,
                projection_identity(vault, Some(mcp_json.as_bytes())),
                1,
                false,
            )
        }
        AgentMutation::SaveGoalSupervision { name, patch } => {
            validate_name(name)?;
            let current = snapshot_sync(root, name)?;
            ensure_revision(&current.revision, expected_revision)?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(conflict(
                    "goal settings cannot shadow an agent owned by another configuration layer",
                ));
            }
            let mut def = crate::agents::parse_agent(
                &current.markdown,
                name,
                PathBuf::from("<daemon-agent-goal-settings-plan>"),
            )
            .map_err(bad_config)?;
            if let Some(value) = &patch.cold_skeptic_count {
                def.goal_supervision.cold_skeptic_count = *value;
            }
            if let Some(value) = &patch.cold_skeptic_model {
                def.goal_supervision.cold_skeptic_model = value.clone();
            }
            if let Some(value) = &patch.max_verification_attempts {
                def.goal_supervision.max_verification_attempts = *value;
            }
            def.goal_supervision.validate().map_err(bad_config)?;
            crate::agents::validate_invariants(&def).map_err(bad_config)?;
            let markdown = def.to_markdown().map_err(bad_config)?;
            (
                "save_goal_supervision",
                Some(name.clone()),
                target_projection_identity(root, name, vault)?,
                projection_identity(vault, Some(markdown.as_bytes())),
                1,
                false,
            )
        }
        AgentMutation::AddMcpServer {
            name,
            server,
            server_json,
            profile,
            secret_values,
        } => {
            validate_name(name)?;
            let current = snapshot_sync(root, name)?;
            ensure_revision(&current.revision, expected_revision)?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict(
                    "agent MCP configuration can only mutate a workspace-owned package",
                ));
            }
            let current_identity = agent_package_projection_identity(root, name, vault)?;
            let update = prepare_agent_mcp_add(
                root,
                name,
                server,
                server_json,
                profile,
                secret_values,
                false,
            )?;
            (
                "add_mcp_server",
                Some(name.clone()),
                current_identity,
                projection_identity(vault, Some(&update.identity_bytes)),
                1,
                false,
            )
        }
    };
    let changed_hint = consumed != intended;
    let affected_hint = if changed_hint { affected_hint } else { 0 };
    Ok(AgentMutationPlan {
        action: action.into(),
        agent_name: name,
        intended_projection_identity: intended,
        consumed_projection_identity: consumed,
        affected_hint,
        changed_hint,
        consumed_config_generation: crate::daemon::server::inventory::current_config_generation(),
        result_is_absent: absent,
    })
}

fn reset_all_projection_identity(vault: &crate::secure_key::SecretVault) -> String {
    let mut digest = Sha256::new();
    digest.update(b"flycockpit.agent-reset-all-targets.v1\0");
    hex::encode(vault.keyed_request_identity(
        b"flycockpit.agent.reset-all-projection.v1",
        digest.finalize().as_slice(),
    ))
}

fn target_projection_identity(
    root: &Path,
    name: &str,
    vault: &crate::secure_key::SecretVault,
) -> Result<String, ErrorPayload> {
    Ok(projection_identity(
        vault,
        current_definition_bytes(root, name)?.as_deref(),
    ))
}

fn current_definition_bytes(root: &Path, name: &str) -> Result<Option<Vec<u8>>, ErrorPayload> {
    let flat = project_agent_path(root, name)?;
    let package = flat.with_file_name(name);
    match std::fs::symlink_metadata(&package) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(conflict(
                "workspace agent package is not an owned directory",
            ));
        }
        Ok(_) => {
            // Projection absence means the whole package directory is gone.
            // A crash after removing only `agent.md` must remain visibly
            // present/divergent instead of being acknowledged as a complete
            // delete while prompts, subagents, or MCP files are orphaned.
            let files = cockpit_host::private_fs::read_nofollow_directory_tree(
                &package,
                1024 * 1024,
                4 * 1024 * 1024,
            )
            .map_err(internal)?;
            return Ok(Some(crate::agents::package_digest_preimage(&files)));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(internal(error)),
    }
    if let Some(bytes) = nofollow_read(&flat)? {
        return Ok(Some(bytes));
    }
    Ok(None)
}

fn intended_definition_bytes(
    root: &Path,
    name: &str,
    markdown: &str,
) -> Result<Vec<u8>, ErrorPayload> {
    let package = project_agent_path(root, name)?.with_file_name(name);
    if package.join("agent.md").is_file() {
        let def = crate::agents::load_owned_definition(
            &package,
            name,
            crate::agents::DefinitionScope::Workspace,
        )
        .map_err(bad_config)?;
        let mut files = def
            .package_files
            .ok_or_else(|| bad_config(anyhow::anyhow!("package load lost package files")))?;
        files.insert("agent.md".to_string(), markdown.as_bytes().to_vec());
        return Ok(crate::agents::package_digest_preimage(&files));
    }
    Ok(markdown.as_bytes().to_vec())
}

struct AgentMcpUpdate {
    markdown: String,
    mcp_json: String,
    identity_bytes: Vec<u8>,
}

fn agent_package_projection_identity(
    root: &Path,
    name: &str,
    vault: &crate::secure_key::SecretVault,
) -> Result<String, ErrorPayload> {
    let def = crate::agents::resolve(root, name)
        .map_err(bad_config)?
        .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?;
    if def.package_files.is_none() {
        return Err(bad_request(
            "agent MCP configuration requires a directory-form agent package",
        ));
    }
    let bytes = def.vnext_digest_bytes().map_err(bad_config)?;
    Ok(projection_identity(vault, Some(&bytes)))
}

fn prepare_agent_mcp_add(
    root: &Path,
    name: &str,
    server_name: &str,
    server_json: &str,
    profile: &str,
    secret_values: &std::collections::BTreeMap<String, cockpit_proto::SensitiveWirePayload>,
    allow_identical_existing: bool,
) -> Result<AgentMcpUpdate, ErrorPayload> {
    if server_name == crate::mcp::builtin::BUILTIN_SERVER_ID {
        return Err(bad_request(
            "the reserved cockpit MCP server cannot be redefined",
        ));
    }
    let mut def = crate::agents::resolve(root, name)
        .map_err(bad_config)?
        .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?;
    let files = def.package_files.as_ref().ok_or_else(|| {
        bad_request("agent MCP configuration requires a directory-form agent package")
    })?;
    let mut config = match files.get("mcp.json") {
        Some(bytes) => crate::mcp::config::McpConfig::parse(
            std::str::from_utf8(bytes)
                .map_err(|_| bad_request("agent package mcp.json is not valid UTF-8"))?,
        )
        .map_err(bad_config)?,
        None => crate::mcp::config::McpConfig::default(),
    };
    let server: crate::mcp::config::ServerConfig =
        serde_json::from_str(server_json).map_err(bad_config)?;
    let mut candidate = crate::mcp::config::McpConfig::default();
    candidate.servers.insert(server_name.to_string(), server);
    crate::daemon::server::validate_and_normalize_mcp_credentials(&mut candidate, secret_values)?;
    let server = candidate
        .servers
        .remove(server_name)
        .expect("inserted above");
    if let Some(existing) = config.servers.get(server_name)
        && (!allow_identical_existing || existing != &server)
    {
        return Err(conflict(format!(
            "MCP server `{server_name}` already exists in agent package `{name}`"
        )));
    }
    server
        .validate_transport_auth(server_name)
        .map_err(bad_config)?;
    let reference_only = server
        .env
        .values()
        .all(|value| value.trim().is_empty() || value.trim_start().starts_with('$'))
        && server.iter_auth_profiles().all(|(_, auth)| match auth {
            crate::mcp::config::Auth::Header(header) => {
                header.value.trim().is_empty() || header.value.trim_start().starts_with('$')
            }
            crate::mcp::config::Auth::Env(env) => env
                .vars
                .values()
                .all(|value| value.trim().is_empty() || value.trim_start().starts_with('$')),
            crate::mcp::config::Auth::Oauth(_) | crate::mcp::config::Auth::None => true,
        });
    if !reference_only {
        return Err(bad_request(
            "agent-package MCP auth must use credential references; literal secrets are refused",
        ));
    }
    server
        .auth_for_profile_named(server_name, profile)
        .map_err(bad_config)?;
    config.servers.insert(server_name.to_string(), server);
    def.mcp_bindings
        .retain(|binding| binding.server != server_name);
    def.mcp_bindings.push(crate::agents::McpBinding {
        server: server_name.to_string(),
        profile: profile.to_string(),
    });
    let markdown = def.to_markdown().map_err(bad_config)?;
    let mcp_json = serde_json::to_string_pretty(&config).map_err(internal)?;
    let files = def.package_files.as_mut().expect("package checked above");
    files.insert("agent.md".to_string(), markdown.as_bytes().to_vec());
    files.insert("mcp.json".to_string(), mcp_json.as_bytes().to_vec());
    let identity_bytes = def.vnext_digest_bytes().map_err(bad_config)?;
    Ok(AgentMcpUpdate {
        markdown,
        mcp_json,
        identity_bytes,
    })
}

fn reset_all_target_projection_identity(
    root: &Path,
    vault: &crate::secure_key::SecretVault,
) -> Result<String, ErrorPayload> {
    let mut entries = crate::agents::BUILTIN_AGENT_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    entries.sort();
    let mut digest = Sha256::new();
    digest.update(b"flycockpit.agent-reset-all-targets.v1\0");
    for name in entries {
        if let Some(bytes) = current_definition_bytes(root, &name)? {
            digest.update((name.len() as u64).to_le_bytes());
            digest.update(name.as_bytes());
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(&bytes);
        }
    }
    Ok(hex::encode(vault.keyed_request_identity(
        b"flycockpit.agent.reset-all-targets.v1",
        digest.finalize().as_slice(),
    )))
}

fn projection_matches_plan(
    root: &Path,
    plan: &AgentMutationPlan,
    vault: &crate::secure_key::SecretVault,
) -> Result<bool, ErrorPayload> {
    if let Some(name) = plan.agent_name.as_deref() {
        if plan.action == "add_mcp_server" {
            return Ok(agent_package_projection_identity(root, name, vault)?
                == plan.intended_projection_identity);
        }
        return Ok(
            target_projection_identity(root, name, vault)? == plan.intended_projection_identity
        );
    }
    Ok(reset_all_target_projection_identity(root, vault)? == plan.intended_projection_identity)
}

fn projection_matches_consumed(
    root: &Path,
    plan: &AgentMutationPlan,
    vault: &crate::secure_key::SecretVault,
) -> Result<bool, ErrorPayload> {
    let current = match plan.agent_name.as_deref() {
        Some(name) if plan.action == "add_mcp_server" => {
            agent_package_projection_identity(root, name, vault)?
        }
        Some(name) => target_projection_identity(root, name, vault)?,
        None => reset_all_target_projection_identity(root, vault)?,
    };
    Ok(current == plan.consumed_projection_identity)
}

fn mutation_tombstone_revision(
    project_root: &str,
    agent_name: Option<&str>,
    result_projection_hash: &str,
) -> String {
    crate::daemon::authority_token::mint(
        b"agent-mutation-tombstone/v1",
        &[
            project_root.as_bytes(),
            agent_name.unwrap_or("*").as_bytes(),
            result_projection_hash.as_bytes(),
        ],
    )
}

fn bind_agent_mutation_receipt(
    result: &mut AgentMutationResult,
    client_operation_id: &str,
    mutation_intent_hash: &str,
    canonical_project_root: &str,
    requested_project_root: &str,
    mutation: &AgentMutation,
) {
    result.client_operation_id = client_operation_id.to_owned();
    result.mutation_intent_hash = mutation_intent_hash.to_owned();
    result.project_root = canonical_project_root.to_owned();
    result.requested_project_root = requested_project_root.to_owned();
    result.owner_scope = format!("project:{canonical_project_root}");
    result.agent_name = cockpit_proto::agent_mutation_name(mutation).map(str::to_owned);
    if result.result_revision.is_empty() {
        result.result_revision = result
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.revision.clone())
            .or_else(|| result.inventory_revision.clone())
            .unwrap_or_else(|| {
                mutation_tombstone_revision(
                    canonical_project_root,
                    cockpit_proto::agent_mutation_name(mutation),
                    &crate::daemon::authority_token::mint(
                        b"agent-absent-projection/v1",
                        &[canonical_project_root.as_bytes()],
                    ),
                )
            });
    }
}

async fn delete_agent_mutation_journal(
    ctx: &DaemonContext,
    owner: &str,
    operation: &str,
) -> Result<(), ErrorPayload> {
    let owner = owner.to_owned();
    let operation = operation.to_owned();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "DELETE FROM agent_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2",
                rusqlite::params![owner, operation],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

async fn compensate_agent_mcp_credentials(
    ctx: &DaemonContext,
    project_root: &str,
    mutations: &std::collections::BTreeMap<String, AgentCredentialMutation>,
) -> Result<(), ErrorPayload> {
    let project_root = project_root.to_owned();
    let mutations = mutations.clone();
    ctx.db
        .transaction(move |conn| {
            let kind = cockpit_db::secret_vault::SecretVaultKind::NamedSecret;
            for (name, record) in &mutations {
                let mutation = &record.vault;
                let current = cockpit_db::secret_vault::load_item_conn(conn, kind, name)?;
                let revision: u64 = conn
                    .query_row(
                        "SELECT revision FROM secret_vault_item_revisions WHERE kind = ?1 AND item_id = ?2",
                        rusqlite::params![kind.as_str(), name],
                        |row| row.get::<_, i64>(0),
                    )?
                    .try_into()?;
                if revision != mutation.after.generation || current != mutation.after.row {
                    continue;
                }
                let next_revision = revision
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("vault item revision overflow"))?;
                match &mutation.prior.row {
                    Some(row) => {
                        conn.execute(
                            "INSERT INTO secret_vault_items
                             (kind,item_id,key_version,nonce,ciphertext,created_at,updated_at,revision)
                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                             ON CONFLICT(kind,item_id) DO UPDATE SET
                               key_version=excluded.key_version,nonce=excluded.nonce,
                               ciphertext=excluded.ciphertext,created_at=excluded.created_at,
                               updated_at=excluded.updated_at,revision=excluded.revision",
                            rusqlite::params![row.kind.as_str(), row.item_id, row.key_version,
                                row.nonce, row.ciphertext, row.created_at, row.updated_at,
                                i64::try_from(next_revision)?],
                        )?;
                    }
                    None => {
                        conn.execute(
                            "DELETE FROM secret_vault_items WHERE kind = ?1 AND item_id = ?2",
                            rusqlite::params![kind.as_str(), name],
                        )?;
                    }
                }
                conn.execute(
                    "INSERT INTO secret_vault_item_revisions (kind,item_id,revision)
                     VALUES (?1,?2,?3)
                     ON CONFLICT(kind,item_id) DO UPDATE SET revision=excluded.revision",
                    rusqlite::params![kind.as_str(), name, i64::try_from(next_revision)?],
                )?;
                if record.ownership_inserted {
                    conn.execute(
                        "DELETE FROM secret_named_ownership
                         WHERE item_id = ?1 AND owner_kind = 'mcp' AND project_root = ?2",
                        rusqlite::params![name, project_root],
                    )?;
                }
            }
            Ok(())
        })
        .await
        .map_err(internal)?;
    ctx.publish_owner_redaction_table().map_err(|error| {
        ctx.poison_redaction_publication(&error);
        ErrorPayload {
            code: ErrorCode::Shutdown,
            message: "agent MCP credential rollback completed but redaction publication failed; restart the daemon".into(),
        }
    })
}

async fn settle_agent_mutation_journal(
    ctx: &DaemonContext,
    owner: String,
    operation: String,
    request_hash: [u8; 32],
    fencing_generation: i64,
    response: &Response,
) -> Result<(), ErrorPayload> {
    let json = serde_json::to_string(response).map_err(internal)?;
    ctx.db
        .transaction(move |conn| {
            let now = chrono::Utc::now().timestamp_millis();
            let journal = conn.execute(
                "UPDATE agent_mutation_journals SET terminal_response_json=?5
                 WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3
                   AND fencing_generation=?4 AND terminal_response_json IS NULL",
                rusqlite::params![owner, operation, request_hash.as_slice(), fencing_generation, json],
            )?;
            if journal != 1 { anyhow::bail!("agent mutation lost its recovery journal"); }
            let receipt = conn.execute(
                "UPDATE local_operation_receipts
                 SET state='terminal_success',terminal_outcome_json=?5,
                     execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                 WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3
                   AND fencing_generation=?4 AND state='executing'",
                rusqlite::params![owner, operation, request_hash.as_slice(), fencing_generation, json, now],
            )?;
            if receipt != 1 { anyhow::bail!("agent mutation lost its receipt fence"); }
            conn.execute(
                "DELETE FROM agent_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2",
                rusqlite::params![owner, operation],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

/// Reconcile hash-only agent publication intents before the daemon socket is
/// visible. A matching intended projection proves that atomic publication
/// crossed its durability boundary; a divergent projection remains pending
/// for explicit repair rather than fabricating either success or rejection.
pub async fn recover_agent_mutation_journals(
    ctx: &DaemonContext,
    publication: crate::daemon::config_publication_recovery::PreSocketConfigPublication,
) -> Result<u64, ErrorPayload> {
    let _publication = crate::daemon::server::inventory::write_authority_publication().await;
    type Row = (
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        i64,
        bool,
        i64,
        String,
        String,
        String,
        String,
    );
    let rows: Vec<Row> = ctx
        .db
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT owner_digest,client_operation_id,request_hash,keyed_request_identity,fencing_generation,
                        project_root,request_project_root,agent_name,action,consumed_revision,affected_hint,changed_hint,consumed_config_generation,
                        mutation_intent_hash,consumed_projection_identity,intended_projection_identity,
                        credential_compensation_json
                   FROM agent_mutation_journals ORDER BY created_at_unix_ms",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
        .await
        .map_err(internal)?;
    let mut recovered = 0_u64;
    for (
        owner,
        operation,
        request_hash,
        keyed_request_identity,
        fencing_generation,
        project_root,
        request_project_root,
        agent_name,
        action,
        consumed_revision,
        affected_hint,
        changed_hint,
        consumed_config_generation,
        mutation_intent_hash,
        consumed_projection_identity,
        intended_projection_identity,
        credential_compensation_json,
    ) in rows
    {
        let Ok(request_hash): Result<[u8; 32], _> = request_hash.try_into() else {
            return Err(internal("agent mutation journal request hash is corrupt"));
        };
        let Ok(stored_keyed_identity): Result<[u8; 32], _> = keyed_request_identity.try_into()
        else {
            return Err(internal(
                "agent mutation journal keyed request identity is corrupt",
            ));
        };
        let expected_keyed_identity = agent_mutation_keyed_identity(
            ctx,
            &owner,
            &operation,
            &project_root,
            &request_project_root,
            &mutation_intent_hash,
        )?;
        if stored_keyed_identity != expected_keyed_identity {
            return Err(internal(
                "agent mutation journal keyed request identity does not match its bindings",
            ));
        }
        let affected_hint = u32::try_from(affected_hint)
            .map_err(|_| internal("agent mutation journal affected count is corrupt"))?;
        let consumed_config_generation = u64::try_from(consumed_config_generation)
            .map_err(|_| internal("agent mutation journal config generation is corrupt"))?;
        let root = PathBuf::from(&project_root);
        let plan = AgentMutationPlan {
            result_is_absent: matches!(
                action.as_str(),
                "delete_custom" | "reset_builtin" | "reset_all_builtins"
            ),
            action,
            agent_name: agent_name.clone(),
            consumed_projection_identity,
            intended_projection_identity,
            affected_hint,
            changed_hint,
            consumed_config_generation,
        };
        let check_root = root.clone();
        let check_plan = plan.clone();
        let check_vault = ctx.secret_vault.clone();
        let lock_target = root.join(".cockpit/config.json");
        let projection_name = agent_name.clone();
        let result_is_absent = plan.result_is_absent;
        let (matches, still_consumed, definition_revision, inventory_revision) = publication
            .with_target(&lock_target, move |_| {
                #[cfg(target_os = "windows")]
                if check_plan.action == "add_mcp_server"
                    && let Some(name) = projection_name.as_deref()
                {
                    recover_windows_agent_package_swap(&check_root, name)
                        .map_err(|error| anyhow::anyhow!(error.message))?;
                }
                let matches = projection_matches_plan(&check_root, &check_plan, &check_vault)
                    .map_err(|error| anyhow::anyhow!(error.message))?;
                let still_consumed = if matches {
                    false
                } else {
                    projection_matches_consumed(&check_root, &check_plan, &check_vault)
                        .map_err(|error| anyhow::anyhow!(error.message))?
                };
                let definition_revision = if matches {
                    match projection_name.as_deref() {
                        Some(name) if !result_is_absent => {
                            current_definition_revision_sync(&check_root, name).ok()
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let inventory_revision = if matches && projection_name.is_none() {
                    current_inventory_revision(&check_root).ok()
                } else {
                    None
                };
                Ok((
                    matches,
                    still_consumed,
                    definition_revision,
                    inventory_revision,
                ))
            })
            .await
            .map_err(|error| ErrorPayload {
                code: ErrorCode::Shutdown,
                message: format!(
                    "bounded agent recovery could not acquire publication authority: {error:#}"
                ),
            })?;
        if !matches {
            let credential_mutations: std::collections::BTreeMap<String, AgentCredentialMutation> =
                serde_json::from_str(&credential_compensation_json).map_err(internal)?;
            compensate_agent_mcp_credentials(ctx, &project_root, &credential_mutations).await?;
            if still_consumed {
                cancel_agent_mutation_journal(
                    ctx,
                    owner,
                    operation,
                    request_hash,
                    fencing_generation,
                )
                .await?;
                recovered = recovered.saturating_add(1);
                continue;
            }
            tracing::warn!(
                client_operation_id = operation,
                "agent mutation recovery projection is divergent; terminalizing settlement as unknown"
            );
            conflict_agent_mutation_journal(
                ctx,
                owner,
                operation,
                request_hash,
                fencing_generation,
            )
            .await?;
            recovered = recovered.saturating_add(1);
            continue;
        }
        let result_revision = definition_revision
            .or_else(|| inventory_revision.clone())
            .unwrap_or_else(|| {
                mutation_tombstone_revision(
                    &project_root,
                    agent_name.as_deref(),
                    &plan.intended_projection_identity,
                )
            });
        // Recovery runs in a fresh process.  A generation persisted by the
        // previous process is evidence about the consumed snapshot, not a
        // generation that this process has ever published.  Publish the
        // recovered file change into the live inventory exactly once; a
        // recovered no-op reports the generation this process actually has.
        let result_config_generation = if changed_hint {
            crate::daemon::server::inventory::publish_committed_config_generation()
        } else {
            crate::daemon::server::inventory::current_config_generation()
        };
        let response = Response::AgentMutated(AgentMutationResult {
            client_operation_id: operation.clone(),
            mutation_intent_hash,
            project_root: project_root.clone(),
            requested_project_root: request_project_root,
            owner_scope: format!("project:{project_root}"),
            agent_name,
            changed: changed_hint,
            affected: affected_hint,
            snapshot: None,
            config_generation: result_config_generation,
            consumed_config_generation,
            result_config_generation,
            inventory_revision,
            consumed_revision,
            result_revision,
            completed_lease_id: None,
            outcome: cockpit_proto::AgentMutationOutcome::CommittedRefreshNeeded {
                warning: "agent files were committed before daemon restart; reload agent settings to reconcile".into(),
            },
        });
        settle_agent_mutation_journal(
            ctx,
            owner,
            operation,
            request_hash,
            fencing_generation,
            &response,
        )
        .await?;
        recovered = recovered.saturating_add(1);
    }
    Ok(recovered)
}

async fn cancel_agent_mutation_journal(
    ctx: &DaemonContext,
    owner: String,
    operation: String,
    request_hash: [u8; 32],
    fencing_generation: i64,
) -> Result<(), ErrorPayload> {
    let error = ErrorPayload {
        code: ErrorCode::Shutdown,
        message: "the daemon restarted before the agent mutation reached file publication".into(),
    };
    let json = serde_json::to_string(&error).map_err(internal)?;
    ctx.db
        .transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE local_operation_receipts
                 SET state='terminal_cancelled',terminal_outcome_json=?5,
                     execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                 WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3
                   AND fencing_generation=?4 AND state='executing'",
                rusqlite::params![
                    owner,
                    operation,
                    request_hash.as_slice(),
                    fencing_generation,
                    json,
                    chrono::Utc::now().timestamp_millis()
                ],
            )?;
            if changed != 1 {
                anyhow::bail!("agent mutation lost its cancellation receipt fence");
            }
            conn.execute(
                "DELETE FROM agent_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2",
                rusqlite::params![owner, operation],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

async fn conflict_agent_mutation_journal(
    ctx: &DaemonContext,
    owner: String,
    operation: String,
    request_hash: [u8; 32],
    fencing_generation: i64,
) -> Result<(), ErrorPayload> {
    let error = ErrorPayload {
        code: ErrorCode::Conflict,
        message: "agent mutation publication is settlement-unknown because the authoritative projection diverged; refresh and submit a new operation".into(),
    };
    let json = serde_json::to_string(&error).map_err(internal)?;
    ctx.db
        .transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE local_operation_receipts
                 SET state='terminal_error',terminal_outcome_json=?5,
                     execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                 WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3
                   AND fencing_generation=?4 AND state='executing'",
                rusqlite::params![
                    owner,
                    operation,
                    request_hash.as_slice(),
                    fencing_generation,
                    json,
                    chrono::Utc::now().timestamp_millis()
                ],
            )?;
            if changed != 1 {
                anyhow::bail!("agent mutation lost its settlement-unknown receipt fence");
            }
            let deleted = conn.execute(
                "DELETE FROM agent_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2",
                rusqlite::params![owner, operation],
            )?;
            if deleted != 1 {
                anyhow::bail!("agent mutation lost its divergent recovery journal");
            }
            Ok(())
        })
        .await
        .map_err(internal)
}

pub async fn begin_editor_lease(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    name: String,
    expected_revision: String,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    // Canonicalize the request before durable lookup so exact replay is bound
    // to workspace identity rather than caller path spelling. This does not
    // consult mutable trust; new authority issuance remains trust-gated below.
    let requested_root = crate::daemon::fs_api::canonical_project_root(&project_root)?;
    let requested_root_text = requested_root.to_string_lossy().into_owned();
    if let Some(existing) = ctx
        .db
        .agent_editor_lease_by_operation(principal_digest.clone(), client_operation_id.clone())
        .await
        .map_err(internal)?
    {
        if existing.project_root != requested_root_text
            || existing.agent_name != name
            || existing.consumed_revision != expected_revision
        {
            return Err(conflict(
                "agent editor client operation was reused for a different request",
            ));
        }
        if existing.state == "terminal" {
            return Err(conflict(
                "agent editor lease acquisition was already settled; start a new editor handoff",
            ));
        }
        if existing.state == "completing" {
            return Err(conflict(
                "agent editor lease completion is already in progress; query the exact completion operation with get_agent_editor_lease_settlement",
            ));
        }
        if existing.expires_at_unix_ms < chrono::Utc::now().timestamp_millis() {
            delete_editor_replay_and_row(ctx, existing).await?;
            return Err(conflict(
                "agent editor lease acquisition expired before it was acknowledged; start a new editor handoff",
            ));
        }
        let snapshot = load_editor_replay(ctx, &existing).await?;
        return Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
            client_operation_id: existing.client_operation_id,
            lease_id: existing.lease_id,
            expires_at_unix_ms: existing.expires_at_unix_ms,
            snapshot,
        }));
    }
    // Exact durable replay is independent of the workspace's current trust
    // configuration. Only issuance of new filesystem authority is trust-gated.
    maintain_editor_leases(ctx).await?;
    let root_text = requested_root_text;
    let root = trusted_canonical_root(ctx, requested_root).await?;
    let snapshot = tokio::task::spawn_blocking({
        let root = root.clone();
        let name = name.clone();
        move || {
            let guard = cockpit_config::config::hold_config_mutation_lock(
                &root.join(".cockpit/config.json"),
            )
            .map_err(internal)?;
            recover_reset_all_locked(&root, &guard)?;
            snapshot_sync(&root, &name)
        }
    })
    .await
    .map_err(join_error)??;
    ensure_revision(&snapshot.revision, Some(&expected_revision))?;
    let lease_id = Uuid::new_v4().to_string();
    let expires_at_unix_ms = chrono::Utc::now().timestamp_millis()
        + i64::try_from(EDITOR_LEASE_TTL.as_millis()).unwrap_or(i64::MAX);
    let replay_plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(&SealedEditorReplay {
            owner_digest: principal_digest.clone(),
            snapshot: snapshot.clone(),
        })
        .map_err(internal)?,
    );
    let snapshot_identity = ctx.secret_vault.keyed_identity(
        b"flycockpit.agent-editor.snapshot.v1",
        replay_plaintext.as_slice(),
    );
    let snapshot_handle = editor_replay_handle(&lease_id);
    let replay_owner = principal_digest.clone();
    let replay_operation = client_operation_id.clone();
    let response_operation = client_operation_id.clone();
    let replay_root = root_text.clone();
    let replay_name = name.clone();
    let replay_revision = expected_revision.clone();
    let row = crate::db::agent_editor_leases::AgentEditorLeaseRow {
        owner_digest: principal_digest,
        client_operation_id,
        lease_id: lease_id.clone(),
        project_root: root_text,
        agent_name: name,
        consumed_revision: expected_revision,
        snapshot_handle: Some(snapshot_handle.clone()),
        snapshot_identity,
        state: "open".into(),
        completion_identity: None,
        completion_handle: None,
        completion_operation_id: None,
        publication_phase: "none".into(),
        consumed_projection_identity: None,
        intended_projection_identity: None,
        publication_result_revision: None,
        consumed_config_generation: None,
        result_config_generation: None,
        terminal_result_json: None,
        terminal_error_json: None,
        expires_at_unix_ms,
        updated_at_unix_ms: chrono::Utc::now().timestamp_millis(),
    };
    let vault = ctx.secret_vault.clone();
    let inserted = ctx
        .db
        .transaction(move |conn| {
            vault
                .mutate_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &snapshot_handle,
                    Some(replay_plaintext.as_slice()),
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            crate::db::agent_editor_leases::insert_agent_editor_lease_conn(conn, &row)?;
            Ok(())
        })
        .await;
    if let Err(insert_error) = inserted {
        // A concurrent duplicate Begin can win the owner/operation unique key
        // after our initial lookup. Replay only an exact binding; never turn a
        // key collision into a second lease.
        let existing = ctx
            .db
            .agent_editor_lease_by_operation(replay_owner, replay_operation)
            .await
            .map_err(internal)?;
        if let Some(existing) = existing
            && existing.project_root == replay_root
            && existing.agent_name == replay_name
            && existing.consumed_revision == replay_revision
        {
            if existing.state == "terminal" {
                return Err(conflict(
                    "agent editor lease acquisition was already settled; start a new editor handoff",
                ));
            }
            if existing.state == "completing" {
                return Err(conflict(
                    "agent editor lease completion is already in progress; query the exact completion operation with get_agent_editor_lease_settlement",
                ));
            }
            if existing.expires_at_unix_ms < chrono::Utc::now().timestamp_millis() {
                delete_editor_replay_and_row(ctx, existing).await?;
                return Err(conflict(
                    "agent editor lease acquisition expired before it was acknowledged; start a new editor handoff",
                ));
            }
            let snapshot = load_editor_replay(ctx, &existing).await?;
            return Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
                client_operation_id: existing.client_operation_id,
                lease_id: existing.lease_id,
                expires_at_unix_ms: existing.expires_at_unix_ms,
                snapshot,
            }));
        }
        return Err(internal(insert_error));
    }
    Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
        client_operation_id: response_operation,
        lease_id,
        expires_at_unix_ms,
        snapshot,
    }))
}

pub async fn complete_editor_lease(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    markdown: Option<cockpit_proto::SensitiveWirePayload>,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    complete_editor_lease_inner(
        ctx,
        client_operation_id,
        project_root,
        lease_id,
        markdown.map(cockpit_proto::SensitiveWirePayload::into_zeroizing),
        principal_digest,
        false,
        None,
    )
    .await
}

async fn complete_editor_lease_inner(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    markdown: Option<zeroize::Zeroizing<String>>,
    principal_digest: String,
    force_reclaim: bool,
    pre_socket_lock_deadline: Option<std::time::Instant>,
) -> Result<Response, ErrorPayload> {
    Uuid::parse_str(&lease_id).map_err(|_| bad_request("invalid editor lease"))?;
    let _publication = crate::daemon::server::inventory::write_authority_publication().await;
    let known_lease = ctx
        .db
        .agent_editor_lease_by_id(lease_id.clone())
        .await
        .map_err(internal)?
        .ok_or_else(|| conflict("editor lease is absent or expired"))?;
    if known_lease.owner_digest != principal_digest {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "agent editor lease belongs to another client principal".into(),
        });
    }
    // Validate every immutable capability target before changing the durable
    // lease state. A typo, stale workspace selection, or malformed persisted
    // snapshot must not poison an otherwise reusable lease by reserving its
    // one completion slot.
    // Completion is an exact capability replay. Do not touch the filesystem
    // merely to normalize a caller-supplied spelling: the canonical root was
    // fixed when Begin issued the lease and is part of the immutable binding.
    if !editor_root_matches(&known_lease.project_root, &project_root)? {
        return Err(bad_request("editor lease belongs to another workspace"));
    }
    let root_text = known_lease.project_root.clone();
    let completion_plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(&(
            "complete_agent_editor_lease",
            &client_operation_id,
            &root_text,
            &lease_id,
            markdown.as_ref().map(|value| value.as_str()),
        ))
        .map_err(internal)?,
    );
    let completion_identity = ctx.secret_vault.keyed_identity(
        b"flycockpit.agent-editor.completion.v2",
        completion_plaintext.as_slice(),
    );
    if known_lease.state == "open" {
        load_editor_replay(ctx, &known_lease).await?;
    }
    if known_lease.state == "terminal" {
        if known_lease.completion_identity != Some(completion_identity) {
            return Err(conflict(
                "agent editor lease was settled by a different completion request",
            ));
        }
        let json = known_lease
            .terminal_result_json
            .as_deref()
            .or(known_lease.terminal_error_json.as_deref())
            .ok_or_else(|| internal("terminal editor lease omitted its receipt"))?;
        let result: AgentEditorCompletion = serde_json::from_str(json).map_err(internal)?;
        if result.client_operation_id != client_operation_id {
            return Err(conflict(
                "agent editor lease was settled by a different client operation",
            ));
        }
        validate_editor_completion_receipt(&known_lease, &result)?;
        return Ok(Response::AgentEditorLeaseCompleted(result));
    }
    // Expiry prevents an unacknowledged Begin from being replayed as apparent
    // success forever; it must not make an already-issued capability
    // impossible to settle. Completion remains exact-hash and owner bound, so
    // a client can reconcile a commit whose response was lost after the TTL.
    let completion_handle = editor_completion_handle(completion_identity);
    let sealed_completion = zeroize::Zeroizing::new(
        serde_json::to_vec(&SealedEditorCompletionRef {
            owner_digest: &principal_digest,
            client_operation_id: &client_operation_id,
            project_root: &root_text,
            lease_id: &lease_id,
            markdown: markdown.as_ref().map(|value| value.as_str()),
        })
        .map_err(internal)?,
    );
    let reservation_lease_id = lease_id.clone();
    let reservation_owner = principal_digest.clone();
    let reservation_operation = client_operation_id.clone();
    let reservation_handle = completion_handle.clone();
    let snapshot_handle = editor_replay_handle(&lease_id);
    let vault = ctx.secret_vault.clone();
    // Sealing the submitted bytes, removing the now-obsolete edit snapshot,
    // and claiming completion authority are one SQLite transaction. There is
    // therefore no crash window with a completing row but no replay evidence.
    let lease = ctx
        .db
        .transaction(move |conn| {
            let claim = crate::db::agent_editor_leases::reserve_agent_editor_completion_conn(
                conn,
                &reservation_lease_id,
                &reservation_owner,
                completion_identity,
                &reservation_handle,
                &reservation_operation,
                force_reclaim,
            )?;
            if matches!(
                claim,
                crate::db::agent_editor_leases::AgentEditorCompletionClaim::Execute(_)
            ) {
                // Only the transaction which wins executable ownership may
                // publish replay material. A terminal/pending retry must not
                // reinsert plaintext after another worker has settled it.
                vault
                    .mutate_item_on_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultKind::SealedState,
                        &reservation_handle,
                        Some(sealed_completion.as_slice()),
                    )
                    .map_err(|error| anyhow::anyhow!(error))?;
                vault
                    .delete_item_on_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultKind::SealedState,
                        &snapshot_handle,
                    )
                    .map_err(|error| anyhow::anyhow!(error))?;
            }
            Ok(claim)
        })
        .await
        .map_err(|error| conflict(error.to_string()))?;
    let mut lease = match lease {
        crate::db::agent_editor_leases::AgentEditorCompletionClaim::Execute(lease) => lease,
        crate::db::agent_editor_leases::AgentEditorCompletionClaim::Pending => {
            return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
                &known_lease,
                &client_operation_id,
                &root_text,
                AgentEditorSettlementStatus::Pending,
            )));
        }
        crate::db::agent_editor_leases::AgentEditorCompletionClaim::Terminal(lease) => lease,
    };
    if let Some(json) = lease.terminal_result_json.as_deref() {
        let result: AgentEditorCompletion = serde_json::from_str(json).map_err(internal)?;
        return Ok(Response::AgentEditorLeaseCompleted(result));
    }
    if let Some(json) = lease.terminal_error_json.as_deref() {
        let result: AgentEditorCompletion = serde_json::from_str(json).map_err(internal)?;
        return Ok(Response::AgentEditorLeaseCompleted(result));
    }
    let completed_lease_id = lease_id.clone();
    let consumed_lease_revision = lease.consumed_revision.clone();
    let is_save = markdown.is_some();
    let result = match markdown {
        Some(mut markdown) => {
            if let Some(result_revision) = lease.publication_result_revision.clone() {
                // This claim durably recorded the revision it published. A
                // later writer may advance the live projection, but cannot
                // make the original commit ambiguous again.
                let consumed_generation = lease.consumed_config_generation.ok_or_else(|| {
                    internal("published editor completion omitted its consumed generation")
                })?;
                let changed =
                    lease.consumed_projection_identity != lease.intended_projection_identity;
                let result_generation = lease.result_config_generation.ok_or_else(|| {
                    internal("published editor completion omitted its result generation")
                })?;
                crate::daemon::server::inventory::publish_committed_config_generation_at_least(
                    result_generation,
                );
                Response::AgentMutated(AgentMutationResult {
                    client_operation_id: client_operation_id.clone(),
                    mutation_intent_hash: crate::daemon::authority_token::mint(
                        b"agent-editor-mutation-intent/v1",
                        &[lease.lease_id.as_bytes(), lease.agent_name.as_bytes()],
                    ),
                    project_root: root_text.clone(),
                    requested_project_root: root_text.clone(),
                    owner_scope: format!("project:{root_text}"),
                    agent_name: Some(lease.agent_name.clone()),
                    changed,
                    affected: u32::from(changed),
                    snapshot: None,
                    config_generation: result_generation,
                    consumed_config_generation: consumed_generation,
                    result_config_generation: result_generation,
                    inventory_revision: None,
                    consumed_revision: Some(consumed_lease_revision.clone()),
                    result_revision,
                    completed_lease_id: None,
                    outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
                })
            } else {
                // New publication authority is trust-gated. An existing
                // durable intent is instead classified under its immutable
                // canonical-root capability; revoked trust only prevents a
                // retry when the consumed bytes are still authoritative.
                let root = PathBuf::from(&root_text);
                let retry_is_trusted = if lease.publication_phase == "none" {
                    trusted_canonical_root(ctx, root.clone()).await?;
                    true
                } else {
                    workspace_is_trusted(ctx, &root).await.unwrap_or(false)
                };
                // Planning, durable intent, authoritative classification,
                // atomic replacement, and publication evidence all occur
                // under the same cross-process lock. A crash can therefore be
                // classified as exact-intended, exact-consumed, or genuinely
                // third-party without attributing another writer's bytes.
                let agent_name = lease.agent_name.clone();
                let consumed_revision = lease.consumed_revision.clone();
                let publication_phase = lease.publication_phase.clone();
                let recorded_consumed_identity = lease.consumed_projection_identity.clone();
                let recorded_intended_identity = lease.intended_projection_identity.clone();
                let recorded_consumed_generation = lease.consumed_config_generation;
                let recorded_result_generation = lease.result_config_generation;
                let publication_db = ctx.db.clone();
                let publication_vault = ctx.secret_vault.clone();
                let publication_lease_id = lease_id.clone();
                let publication_operation_id = client_operation_id.clone();
                match tokio::task::spawn_blocking(move || {
                    let lock_target = root.join(".cockpit/config.json");
                    let guard = if let Some(deadline) = pre_socket_lock_deadline {
                        let Some(guard) =
                            cockpit_config::config::try_hold_config_mutation_lock_until(
                                &lock_target,
                                deadline,
                            )
                            .map_err(internal)?
                        else {
                            return Ok(EditorPublicationAttempt::Pending(ErrorPayload {
                                code: ErrorCode::Shutdown,
                                message: "editor completion remains pending because the config mutation lock was busy during bounded boot recovery".into(),
                            }));
                        };
                        guard
                    } else {
                        cockpit_config::config::hold_config_mutation_lock(&lock_target)
                            .map_err(internal)?
                    };
                    let mutation = AgentMutation::SaveDefinition {
                        name: agent_name.clone(),
                        markdown: std::mem::take(&mut *markdown),
                    };
                    let (consumed_identity, intended_identity, consumed_generation, result_generation) =
                        if publication_phase == "none" {
                            recover_reset_all_locked(&root, &guard)?;
                            let plan = prepare_mutation_plan_sync(
                                &root,
                                &mutation,
                                Some(&consumed_revision),
                                &publication_vault,
                            )?;
                            let consumed_generation = plan.consumed_config_generation;
                            let result_generation = if plan.changed_hint {
                                consumed_generation.checked_add(1).ok_or_else(|| {
                                    internal("agent editor config generation overflow")
                                })?
                            } else {
                                consumed_generation
                            };
                            publication_db.prepare_agent_editor_publication_under_publication_lock(
                                crate::db::agent_editor_leases::AgentEditorPublicationIntent {
                                    lease_id: publication_lease_id.clone(),
                                    completion_identity,
                                    completion_operation_id: publication_operation_id.clone(),
                                    consumed_projection_identity: plan.consumed_projection_identity.clone(),
                                    intended_projection_identity: plan.intended_projection_identity.clone(),
                                    consumed_config_generation: consumed_generation,
                                    result_config_generation: result_generation,
                                },
                            )
                            .map_err(internal)?;
                            (
                                plan.consumed_projection_identity,
                                plan.intended_projection_identity,
                                consumed_generation,
                                result_generation,
                            )
                        } else {
                            (
                                recorded_consumed_identity.ok_or_else(|| {
                                    internal("editor publication intent omitted consumed identity")
                                })?,
                                recorded_intended_identity.ok_or_else(|| {
                                    internal("editor publication intent omitted intended identity")
                                })?,
                                recorded_consumed_generation.ok_or_else(|| {
                                    internal("editor publication intent omitted consumed generation")
                                })?,
                                recorded_result_generation.ok_or_else(|| {
                                    internal("editor publication intent omitted result generation")
                                })?,
                            )
                        };
                    let authoritative_identity =
                        target_projection_identity(&root, &agent_name, &publication_vault)?;
                    if authoritative_identity == intended_identity {
                        let result_revision =
                            current_definition_revision_sync(&root, &agent_name)?;
                        let changed = consumed_identity != intended_identity;
                        if publication_phase != "published" {
                            publication_db.record_agent_editor_publication_under_publication_lock(
                                publication_lease_id.clone(),
                                completion_identity,
                                publication_operation_id.clone(),
                                result_revision.clone(),
                            )
                            .map_err(internal)?;
                        }
                        crate::daemon::server::inventory::publish_committed_config_generation_at_least(result_generation);
                        return Ok(EditorPublicationAttempt::Published(Response::AgentMutated(AgentMutationResult {
                            client_operation_id: publication_operation_id,
                            mutation_intent_hash: crate::daemon::authority_token::mint(
                                b"agent-editor-mutation-intent/v1",
                                &[publication_lease_id.as_bytes(), agent_name.as_bytes()],
                            ),
                            project_root: root.to_string_lossy().into_owned(),
                            requested_project_root: root.to_string_lossy().into_owned(),
                            owner_scope: format!("project:{}", root.to_string_lossy()),
                            agent_name: Some(agent_name),
                            changed,
                            affected: u32::from(changed),
                            result_revision,
                            snapshot: None,
                            config_generation: result_generation,
                            consumed_config_generation: consumed_generation,
                            result_config_generation: result_generation,
                            inventory_revision: None,
                            consumed_revision: Some(consumed_revision),
                            completed_lease_id: None,
                            outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
                        })));
                    }
                    if authoritative_identity != consumed_identity {
                        return Ok(EditorPublicationAttempt::Pending(ErrorPayload {
                            code: ErrorCode::Shutdown,
                            message: "editor publication settlement is unknown because the authoritative file matches neither the consumed nor intended projection".into(),
                        }));
                    }
                    if !retry_is_trusted {
                        return Ok(EditorPublicationAttempt::Pending(ErrorPayload {
                            code: ErrorCode::WorkspaceTrust,
                            message: "editor publication intent remains pending because workspace trust was revoked before the consumed projection could be retried".into(),
                        }));
                    }
                    // Recovery journals may themselves publish agent bytes.
                    // Run them only after trust is confirmed, then classify
                    // the editor target again before attempting this write.
                    recover_reset_all_locked(&root, &guard)?;
                    let after_recovery_identity =
                        target_projection_identity(&root, &agent_name, &publication_vault)?;
                    if after_recovery_identity == intended_identity {
                        let result_revision =
                            current_definition_revision_sync(&root, &agent_name)?;
                        publication_db.record_agent_editor_publication_under_publication_lock(
                            publication_lease_id.clone(),
                            completion_identity,
                            publication_operation_id.clone(),
                            result_revision.clone(),
                        )
                        .map_err(internal)?;
                        crate::daemon::server::inventory::publish_committed_config_generation_at_least(result_generation);
                        let changed = consumed_identity != intended_identity;
                        return Ok(EditorPublicationAttempt::Published(Response::AgentMutated(
                            AgentMutationResult {
                                client_operation_id: publication_operation_id,
                                mutation_intent_hash: crate::daemon::authority_token::mint(
                                    b"agent-editor-mutation-intent/v1",
                                    &[publication_lease_id.as_bytes(), agent_name.as_bytes()],
                                ),
                                project_root: root.to_string_lossy().into_owned(),
                                requested_project_root: root.to_string_lossy().into_owned(),
                                owner_scope: format!("project:{}", root.to_string_lossy()),
                                agent_name: Some(agent_name),
                                changed,
                                affected: u32::from(changed),
                                result_revision,
                                snapshot: None,
                                config_generation: result_generation,
                                consumed_config_generation: consumed_generation,
                                result_config_generation: result_generation,
                                inventory_revision: None,
                                consumed_revision: Some(consumed_revision),
                                completed_lease_id: None,
                                outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
                            },
                        )));
                    }
                    if after_recovery_identity != consumed_identity {
                        return Ok(EditorPublicationAttempt::Pending(ErrorPayload {
                            code: ErrorCode::Shutdown,
                            message: "editor publication settlement changed while trusted recovery was running; the authoritative projection matches neither the consumed nor intended bytes".into(),
                        }));
                    }
                    let response = match mutate_sync_locked(
                        &root,
                        mutation,
                        Some(consumed_revision.clone()),
                        &guard,
                        Some((consumed_generation, result_generation)),
                    ) {
                        Ok(response) => response,
                        Err(mutation_error) => {
                            // Error codes cannot prove whether atomic replace
                            // crossed its durability boundary. Re-read the
                            // exact target while still holding the publication
                            // lock and classify only from keyed identities.
                            let authoritative_identity = match target_projection_identity(
                                &root,
                                &agent_name,
                                &publication_vault,
                            ) {
                                Ok(identity) => identity,
                                Err(classification_error) => {
                                    return Ok(EditorPublicationAttempt::Pending(
                                        classification_error,
                                    ));
                                }
                            };
                            if authoritative_identity == intended_identity {
                                let result_revision = match current_definition_revision_sync(
                                    &root,
                                    &agent_name,
                                ) {
                                    Ok(revision) => revision,
                                    Err(classification_error) => {
                                        return Ok(EditorPublicationAttempt::Pending(
                                            classification_error,
                                        ));
                                    }
                                };
                                publication_db
                                    .record_agent_editor_publication_under_publication_lock(
                                        publication_lease_id.clone(),
                                        completion_identity,
                                        publication_operation_id.clone(),
                                        result_revision.clone(),
                                    )
                                    .map_err(internal)?;
                                let changed = consumed_identity != intended_identity;
                                crate::daemon::server::inventory::publish_committed_config_generation_at_least(result_generation);
                                return Ok(EditorPublicationAttempt::Published(
                                    Response::AgentMutated(AgentMutationResult {
                                        client_operation_id: publication_operation_id,
                                        mutation_intent_hash:
                                            crate::daemon::authority_token::mint(
                                                b"agent-editor-mutation-intent/v1",
                                                &[
                                                    publication_lease_id.as_bytes(),
                                                    agent_name.as_bytes(),
                                                ],
                                            ),
                                        project_root: root.to_string_lossy().into_owned(),
                                        requested_project_root: root
                                            .to_string_lossy()
                                            .into_owned(),
                                        owner_scope: format!(
                                            "project:{}",
                                            root.to_string_lossy()
                                        ),
                                        agent_name: Some(agent_name),
                                        changed,
                                        affected: u32::from(changed),
                                        result_revision,
                                        snapshot: None,
                                        config_generation: result_generation,
                                        consumed_config_generation: consumed_generation,
                                        result_config_generation: result_generation,
                                        inventory_revision: None,
                                        consumed_revision: Some(consumed_revision),
                                        completed_lease_id: None,
                                        outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
                                    }),
                                ));
                            }
                            if authoritative_identity == consumed_identity {
                                return Ok(EditorPublicationAttempt::Rejected(mutation_error));
                            }
                            return Ok(EditorPublicationAttempt::Pending(mutation_error));
                        }
                    };
                    if let Response::AgentMutated(mutation) = &response {
                        publication_db.record_agent_editor_publication_under_publication_lock(
                            publication_lease_id,
                            completion_identity,
                            publication_operation_id,
                            mutation.result_revision.clone(),
                        )
                        .map_err(internal)?;
                    }
                    Ok(EditorPublicationAttempt::Published(response))
                })
                .await
                .map_err(join_error)
                .and_then(|result| result)
                {
                    Ok(EditorPublicationAttempt::Published(result)) => result,
                    Ok(EditorPublicationAttempt::Rejected(error)) => {
                        let receipt = editor_completion(
                            &lease,
                            &client_operation_id,
                            &root_text,
                            AgentEditorSettlementStatus::Rejected {
                                error: ErrorPayload {
                                    code: error.code,
                                    message:
                                        "the editor completion was rejected before publication"
                                            .into(),
                                },
                            },
                        );
                        let json = serde_json::to_string(&receipt).map_err(internal)?;
                        let vault = ctx.secret_vault.clone();
                        let handle = completion_handle.clone();
                        let rejected_lease_id = lease_id.clone();
                        let operation_id = client_operation_id.clone();
                        ctx.db
                            .transaction(move |conn| {
                                vault
                                    .delete_item_on_conn(
                                        conn,
                                        cockpit_db::secret_vault::SecretVaultKind::SealedState,
                                        &handle,
                                    )
                                    .map_err(|error| anyhow::anyhow!(error))?;
                                crate::db::agent_editor_leases::fail_agent_editor_completion_conn(
                                    conn,
                                    &rejected_lease_id,
                                    completion_identity,
                                    &operation_id,
                                    &json,
                                )
                            })
                            .await
                            .map_err(internal)?;
                        return Ok(Response::AgentEditorLeaseCompleted(receipt));
                    }
                    Ok(EditorPublicationAttempt::Pending(error)) | Err(error) => {
                        tracing::warn!(
                            error = %error.message,
                            lease_id,
                            "editor completion write settlement is ambiguous; retaining sealed payload"
                        );
                        return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
                            &lease,
                            &client_operation_id,
                            &root_text,
                            AgentEditorSettlementStatus::Pending,
                        )));
                    }
                }
            }
        }
        None => {
            let generation = crate::daemon::server::inventory::current_config_generation();
            Response::AgentMutated(AgentMutationResult {
                client_operation_id: client_operation_id.clone(),
                mutation_intent_hash: crate::daemon::authority_token::mint(
                    b"agent-editor-cancel-intent/v1",
                    &[lease.lease_id.as_bytes(), lease.agent_name.as_bytes()],
                ),
                project_root: root_text.clone(),
                requested_project_root: root_text.clone(),
                owner_scope: format!("project:{root_text}"),
                agent_name: Some(lease.agent_name.clone()),
                changed: false,
                affected: 0,
                snapshot: None,
                config_generation: generation,
                consumed_config_generation: generation,
                result_config_generation: generation,
                inventory_revision: None,
                consumed_revision: Some(consumed_lease_revision),
                result_revision: lease.consumed_revision.clone(),
                completed_lease_id: None,
                outcome: cockpit_proto::AgentMutationOutcome::Reconciled,
            })
        }
    };
    let Response::AgentMutated(mut result) = result else {
        unreachable!("agent mutation always returns AgentMutated")
    };
    if let Some(mut discarded_snapshot) = result.snapshot.take() {
        zeroize_agent_edit_snapshot(&mut discarded_snapshot);
    }
    lease.consumed_config_generation = Some(result.consumed_config_generation);
    lease.result_config_generation = Some(result.result_config_generation);
    result.completed_lease_id = Some(completed_lease_id);
    let status = if is_save {
        let result_revision = result.result_revision.clone();
        AgentEditorSettlementStatus::Saved {
            result_revision,
            outcome: result.outcome.clone(),
        }
    } else {
        AgentEditorSettlementStatus::Cancelled
    };
    // Durable settlement is a typed metadata receipt, not another copy of the
    // agent document. A replay can refresh the authoritative snapshot.
    let receipt = editor_completion(&lease, &client_operation_id, &root_text, status);
    let result_json = match serde_json::to_string(&receipt) {
        Ok(json) => json,
        Err(error) => {
            tracing::warn!(error = %error, lease_id, "editor settlement receipt encoding is unresolved");
            return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
                &lease,
                &client_operation_id,
                &root_text,
                AgentEditorSettlementStatus::Pending,
            )));
        }
    };
    let vault = ctx.secret_vault.clone();
    let terminal_completion_handle = completion_handle;
    let settlement_operation_id = client_operation_id.clone();
    if let Err(error) = ctx
        .db
        .transaction(move |conn| {
            vault
                .delete_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::SealedState,
                    &terminal_completion_handle,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            crate::db::agent_editor_leases::finish_agent_editor_completion_conn(
                conn,
                &lease_id,
                completion_identity,
                &settlement_operation_id,
                &result_json,
                result.consumed_config_generation,
                result.result_config_generation,
            )
        })
        .await
    {
        // The filesystem mutation may already be durable. Leave the exact
        // completion identity claimed so retry/restart reconciliation checks
        // authoritative content rather than reporting a false failure.
        tracing::warn!(error = %error, "editor settlement receipt persistence is unresolved");
        return Ok(Response::AgentEditorLeaseCompleted(editor_completion(
            &lease,
            &client_operation_id,
            &root_text,
            AgentEditorSettlementStatus::Pending,
        )));
    }
    Ok(Response::AgentEditorLeaseCompleted(receipt))
}

pub async fn editor_lease_settlement(
    ctx: &DaemonContext,
    client_operation_id: String,
    project_root: String,
    lease_id: String,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    Uuid::parse_str(&lease_id).map_err(|_| bad_request("invalid editor lease"))?;
    let row = ctx
        .db
        .agent_editor_lease_by_id(lease_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| conflict("editor lease is absent or expired"))?;
    if row.owner_digest != principal_digest {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "agent editor lease belongs to another client principal".into(),
        });
    }
    // Settlement is metadata-only and exact-root-bound. It must remain
    // queryable after the workspace disappears or trust is revoked.
    if !editor_root_matches(&row.project_root, &project_root)? {
        return Err(bad_request("editor lease belongs to another workspace"));
    }
    let root_text = row.project_root.clone();
    let status = match (row.state.as_str(), row.completion_operation_id.as_deref()) {
        ("open", None) => AgentEditorSettlementStatus::NotStarted,
        (_, None) => {
            return Err(internal(
                "reserved editor lease omitted its completion operation",
            ));
        }
        (_, Some(operation)) if operation != client_operation_id => {
            return Err(conflict(
                "agent editor lease was settled by a different client operation",
            ));
        }
        // Age only controls which daemon recovery worker may reclaim the
        // executor claim. Once reserved, publication may already be durable,
        // so the client must never be told that this operation was not started.
        ("completing", Some(_)) => AgentEditorSettlementStatus::Pending,
        ("terminal", Some(_)) => {
            let json = row
                .terminal_result_json
                .as_deref()
                .or(row.terminal_error_json.as_deref())
                .ok_or_else(|| internal("terminal editor lease omitted its receipt"))?;
            let receipt: AgentEditorCompletion = serde_json::from_str(json).map_err(internal)?;
            validate_editor_completion_receipt(&row, &receipt)?;
            return Ok(Response::AgentEditorLeaseCompleted(receipt));
        }
        (state, Some(_)) => {
            return Err(internal(format!(
                "editor lease has unsupported settlement state {state}"
            )));
        }
    };
    Ok(Response::AgentEditorLeaseCompleted(editor_completion(
        &row,
        &client_operation_id,
        &root_text,
        status,
    )))
}

fn editor_completion(
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
    client_operation_id: &str,
    project_root: &str,
    status: AgentEditorSettlementStatus,
) -> AgentEditorCompletion {
    let (consumed_config_generation, result_config_generation) = match &status {
        AgentEditorSettlementStatus::Saved { .. } | AgentEditorSettlementStatus::Cancelled => {
            (row.consumed_config_generation, row.result_config_generation)
        }
        AgentEditorSettlementStatus::NotStarted
        | AgentEditorSettlementStatus::Pending
        | AgentEditorSettlementStatus::Rejected { .. } => (None, None),
    };
    AgentEditorCompletion {
        client_operation_id: client_operation_id.to_owned(),
        project_root: project_root.to_owned(),
        owner_scope: format!("project:{project_root}"),
        agent_name: row.agent_name.clone(),
        lease_id: row.lease_id.clone(),
        consumed_revision: row.consumed_revision.clone(),
        consumed_config_generation,
        result_config_generation,
        status,
    }
}

fn zeroize_agent_edit_snapshot(snapshot: &mut AgentEditSnapshot) {
    zeroize::Zeroize::zeroize(&mut snapshot.name);
    zeroize::Zeroize::zeroize(&mut snapshot.markdown);
    zeroize::Zeroize::zeroize(&mut snapshot.canonical_preview);
    zeroize::Zeroize::zeroize(&mut snapshot.source_identity);
    zeroize::Zeroize::zeroize(&mut snapshot.revision);
    zeroize::Zeroize::zeroize(&mut snapshot.goal_supervision_json);
    zeroize::Zeroize::zeroize(&mut snapshot.projection_digest);
}

fn validate_editor_completion_receipt(
    row: &crate::db::agent_editor_leases::AgentEditorLeaseRow,
    receipt: &AgentEditorCompletion,
) -> Result<(), ErrorPayload> {
    if receipt.client_operation_id != row.completion_operation_id.as_deref().unwrap_or_default()
        || receipt.project_root != row.project_root
        || receipt.owner_scope != format!("project:{}", row.project_root)
        || receipt.agent_name != row.agent_name
        || receipt.lease_id != row.lease_id
        || receipt.consumed_revision != row.consumed_revision
    {
        return Err(internal("editor completion receipt binding mismatch"));
    }
    if matches!(
        &receipt.status,
        AgentEditorSettlementStatus::Saved { .. } | AgentEditorSettlementStatus::Cancelled
    ) && (receipt.consumed_config_generation != row.consumed_config_generation
        || receipt.result_config_generation != row.result_config_generation)
    {
        return Err(internal("editor completion generation binding mismatch"));
    }
    cockpit_proto::validate_agent_editor_completion(
        receipt,
        receipt.client_operation_id.as_str(),
        &row.project_root,
        &row.agent_name,
        &row.lease_id,
        &row.consumed_revision,
    )
    .map_err(internal)?;
    Ok(())
}

fn editor_root_matches(canonical_root: &str, requested_root: &str) -> Result<bool, ErrorPayload> {
    // Exact replay remains possible after the workspace has disappeared.
    // Otherwise normalize relative/symlink spellings without consulting the
    // mutable trust database; the lease itself is the durable capability.
    if canonical_root == requested_root {
        return Ok(true);
    }
    Ok(crate::daemon::fs_api::canonical_project_root(requested_root)? == Path::new(canonical_root))
}

async fn trusted_root(ctx: &DaemonContext, root: &str) -> Result<PathBuf, ErrorPayload> {
    let root = crate::daemon::fs_api::canonical_project_root(root)?;
    trusted_canonical_root(ctx, root).await
}

async fn trusted_canonical_root(
    ctx: &DaemonContext,
    root: PathBuf,
) -> Result<PathBuf, ErrorPayload> {
    let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
        .await
        .map_err(|error| ErrorPayload {
            code: ErrorCode::WorkspaceTrust,
            message: format!("workspace trust is required for agent management: {error:#}"),
        })?;
    if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
        return Err(ErrorPayload {
            code: ErrorCode::WorkspaceTrust,
            message: "agent management requires a trusted workspace".into(),
        });
    }
    Ok(root)
}

async fn workspace_is_trusted(ctx: &DaemonContext, root: &Path) -> Result<bool, ErrorPayload> {
    let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, root)
        .await
        .map_err(internal)?;
    Ok(policy.mode == crate::db::workspace_trust::WorkspaceTrustMode::Trust)
}

fn inventory_sync(
    root: &Path,
    requested_project_root: &str,
    expected_config_generation: u64,
    guard: &cockpit_config::config::HeldConfigMutationLock,
) -> Result<Response, ErrorPayload> {
    recover_reset_all_locked(root, guard)?;
    let entries = inventory_entries(root)?;
    let inventory_revision = inventory_revision(&entries);
    let config_generation = crate::daemon::server::inventory::current_config_generation();
    if config_generation != expected_config_generation {
        return Err(conflict(
            "configuration changed while reading agent inventory; retry the paired read",
        ));
    }
    Ok(Response::AgentInventory {
        entries,
        inventory_revision,
        project_root: root.to_string_lossy().into_owned(),
        requested_project_root: requested_project_root.to_owned(),
        config_generation,
    })
}

fn inventory_entries(root: &Path) -> Result<Vec<AgentInventoryEntry>, ErrorPayload> {
    let all = crate::agents::list_all(root);
    if all.len() > cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES {
        return Err(bad_request(format!(
            "agent inventory exceeds the {}-entry local response limit; remove unused definitions",
            cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES
        )));
    }
    all.into_iter()
        .map(|entry| {
            let source = source_snapshot_parts(root, &entry.name).or_else(|error| {
                let Some(path) = crate::agents::find_override(root, &entry.name) else {
                    return Err(error);
                };
                let metadata = std::fs::symlink_metadata(&path).map_err(internal)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(error);
                }
                let target = project_agent_path(root, &entry.name)?;
                let layer = classify_source_layer(root, &path, &target);
                Ok((
                    layer,
                    opaque_source_identity(root, &path, layer, b"")?,
                    String::new(),
                    nofollow_read(&target)?.is_some(),
                ))
            });
            let (description, model, valid, diagnostic) = match entry.def {
                Ok(def) => (Some(def.description), def.model, true, None),
                Err(_) => (
                    None,
                    None,
                    false,
                    Some(
                        "agent definition is invalid; inspect it through the daemon editor".into(),
                    ),
                ),
            };
            if [
                description.as_deref(),
                model.as_deref(),
                diagnostic.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES)
            {
                return Err(bad_request(format!(
                    "agent `{}` metadata exceeds the safe local response bounds",
                    entry.name
                )));
            }
            let (source_layer, source_identity, markdown, target_exists) = source?;
            let revision = definition_revision(
                &entry.name,
                source_layer,
                &source_identity,
                &crate::assistants::markdown_content_hash(&markdown),
                target_exists,
            );
            Ok(AgentInventoryEntry {
                name: entry.name,
                kind: match entry.kind {
                    crate::agents::AgentKind::Builtin { .. } => AgentEntryKind::Builtin,
                    crate::agents::AgentKind::Custom => AgentEntryKind::Custom,
                },
                overridden: matches!(
                    entry.kind,
                    crate::agents::AgentKind::Builtin { overridden: true }
                ),
                description,
                model,
                valid,
                diagnostic,
                source_layer,
                source_identity: source_identity.to_string(),
                revision,
                editable: source_layer == AgentSourceLayer::Workspace && !markdown.is_empty(),
                projection_digest: String::new(),
            })
        })
        .collect()
}

fn snapshot_sync(root: &Path, name: &str) -> Result<AgentEditSnapshot, ErrorPayload> {
    validate_name(name)?;
    let def = crate::agents::resolve(root, name)
        .map_err(bad_config)?
        .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?;
    let canonical_preview = def.to_markdown().map_err(bad_config)?;
    if canonical_preview.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
        return Err(bad_request(format!(
            "canonical agent preview exceeds the {}-byte local editor limit",
            cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
        )));
    }
    let (source_layer, source_identity, markdown, target_exists) =
        source_snapshot_parts(root, name)?;
    let revision = definition_revision(
        name,
        source_layer,
        &source_identity,
        &crate::assistants::markdown_content_hash(&markdown),
        target_exists,
    );
    let goal_supervision_json = (!def.goal_supervision.is_empty())
        .then(|| serde_json::to_string(&def.goal_supervision).map_err(bad_config))
        .transpose()?;
    if goal_supervision_json
        .as_ref()
        .is_some_and(|value| value.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES)
    {
        return Err(bad_request(
            "agent goal supervision projection is too large",
        ));
    }
    Ok(AgentEditSnapshot {
        name: name.to_string(),
        kind: if crate::agents::is_builtin_agent(name) {
            AgentEntryKind::Builtin
        } else {
            AgentEntryKind::Custom
        },
        overridden: source_layer != AgentSourceLayer::Embedded,
        markdown: markdown.to_string(),
        canonical_preview,
        source_layer,
        source_identity: source_identity.to_string(),
        edit_target: AgentEditTarget::Workspace,
        revision,
        goal_supervision_json,
        editable: source_layer == AgentSourceLayer::Workspace,
        supports_goal_supervision: def.vnext.is_none(),
        projection_digest: String::new(),
    })
}

/// Compute the authoritative definition revision without constructing an
/// `AgentEditSnapshot`. Recovery needs only this metadata and must not create
/// extra ordinary copies of editor markdown that will immediately be dropped.
fn current_definition_revision_sync(root: &Path, name: &str) -> Result<String, ErrorPayload> {
    validate_name(name)?;
    let (source_layer, source_identity, markdown, target_exists) =
        source_snapshot_parts(root, name)?;
    let markdown = zeroize::Zeroizing::new(markdown);
    Ok(definition_revision(
        name,
        source_layer,
        &source_identity,
        &crate::assistants::markdown_content_hash(markdown.as_str()),
        target_exists,
    ))
}

fn source_snapshot_parts(
    root: &Path,
    name: &str,
) -> Result<(AgentSourceLayer, String, String, bool), ErrorPayload> {
    let project_override = project_agent_path(root, name)?;
    let write_target = project_agent_write_path(root, name)?;
    let target_exists =
        nofollow_read(&project_override)?.is_some() || nofollow_read(&write_target)?.is_some();
    match crate::agents::find_override(root, name) {
        Some(source) => {
            let meta = std::fs::symlink_metadata(&source).map_err(internal)?;
            if meta.file_type().is_symlink() {
                return Err(conflict("agent source became a symlink while snapshotting"));
            }
            let (markdown, identity_bytes) = if meta.file_type().is_dir() {
                let def = crate::agents::resolve(root, name)
                    .map_err(bad_config)?
                    .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?;
                let markdown = match def
                    .package_files
                    .as_ref()
                    .and_then(|files| files.get("agent.md").cloned())
                {
                    Some(bytes) => String::from_utf8(bytes)
                        .map_err(|_| bad_request("agent definition is not valid UTF-8"))?,
                    None => def.to_markdown().map_err(bad_config)?,
                };
                let identity_bytes = def.vnext_digest_bytes().map_err(bad_config)?;
                (markdown, identity_bytes)
            } else {
                let raw = nofollow_read(&source)?.ok_or_else(|| {
                    conflict("agent source changed while the snapshot was being acquired")
                })?;
                let markdown = String::from_utf8(raw.clone())
                    .map_err(|_| bad_request("agent definition is not valid UTF-8"))?;
                (markdown, raw)
            };
            if markdown.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
                return Err(bad_request(format!(
                    "agent definition exceeds the {}-byte local editor limit",
                    cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
                )));
            }
            let layer = classify_source_layer(root, &source, &project_override);
            let identity = opaque_source_identity(root, &source, layer, &identity_bytes)?;
            Ok((layer, identity, markdown, target_exists))
        }
        None => {
            let markdown = crate::agents::resolve(root, name)
                .map_err(bad_config)?
                .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?
                .to_markdown()
                .map_err(bad_config)?;
            if markdown.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
                return Err(bad_request(format!(
                    "embedded agent definition exceeds the {}-byte local editor limit",
                    cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
                )));
            }
            let identity = embedded_source_identity(root, name, markdown.as_bytes());
            Ok((
                AgentSourceLayer::Embedded,
                identity,
                markdown,
                target_exists,
            ))
        }
    }
}

fn mutate_sync_locked(
    root: &Path,
    mutation: AgentMutation,
    expected_revision: Option<String>,
    guard: &cockpit_config::config::HeldConfigMutationLock,
    durable_generation_pair: Option<(u64, u64)>,
) -> Result<Response, ErrorPayload> {
    let mutation_name = cockpit_proto::agent_mutation_name(&mutation).map(str::to_owned);
    let project_root = root.to_string_lossy().into_owned();
    let consumed_revision = expected_revision.clone();
    recover_reset_all_locked(root, guard)?;
    let generation_before = durable_generation_pair
        .map(|(consumed, _)| consumed)
        .unwrap_or_else(crate::daemon::server::inventory::current_config_generation);
    let resets_inventory = matches!(&mutation, AgentMutation::ResetAllBuiltins);
    let changes_mcp_binding = matches!(&mutation, AgentMutation::AddMcpServer { .. });
    let (changed, affected, snapshot) = match mutation {
        AgentMutation::EjectBuiltin { name } => {
            validate_name(&name)?;
            if !crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("only a built-in agent can be ejected"));
            }
            let before = snapshot_sync(root, &name)?;
            ensure_revision(&before.revision, expected_revision.as_deref())?;
            ensure_workspace_source_or_embedded(&before)?;
            let target = project_agent_write_path(root, &name)?;
            if nofollow_read(&target)?.is_some() {
                (false, 0, Some(snapshot_sync(root, &name)?))
            } else {
                let parent = target.parent().expect("agent path has parent");
                std::fs::create_dir_all(parent).map_err(internal)?;
                cockpit_config::config::write_config_bytes_atomic(
                    &target,
                    before.markdown.as_bytes(),
                )
                .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
        AgentMutation::SaveDefinition { name, markdown } => {
            let markdown = zeroize::Zeroizing::new(markdown);
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(conflict(
                    "save refused: another configuration layer owns this agent",
                ));
            }
            let parsed =
                crate::agents::parse_agent(&markdown, &name, PathBuf::from("<daemon-agent-edit>"))
                    .map_err(bad_config)?;
            crate::agents::validate_invariants(&parsed).map_err(bad_config)?;
            let target = project_agent_write_path(root, &name)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            let old = nofollow_read(&target)?;
            if old.as_deref() == Some(markdown.as_bytes()) {
                (false, 0, Some(current))
            } else {
                cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                    .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
        AgentMutation::CreateDefinition { name, markdown } => {
            validate_name(&name)?;
            if crate::agents::resolve(root, &name)
                .map_err(bad_config)?
                .is_some()
            {
                return Err(conflict(
                    "agent name already resolves in a configuration layer",
                ));
            }
            let target = project_agent_path(root, &name)?;
            if nofollow_read(&target)?.is_some() {
                return Err(conflict("workspace agent already exists"));
            }
            if expected_revision.is_some() {
                return Err(bad_request(
                    "create uses the daemon's authoritative absence check, not a document revision",
                ));
            }
            let parsed = crate::agents::parse_agent(
                &markdown,
                &name,
                PathBuf::from("<daemon-agent-create>"),
            )
            .map_err(bad_config)?;
            crate::agents::validate_invariants(&parsed).map_err(bad_config)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                .map_err(internal)?;
            (true, 1, Some(snapshot_sync(root, &name)?))
        }
        AgentMutation::DeleteCustom { name } => {
            validate_name(&name)?;
            if crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("built-in agents cannot be deleted"));
            }
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict("custom agent is not owned by the workspace layer"));
            }
            let affected = delete_custom_atomic_locked(root, guard, &name)?;
            (affected != 0, affected, None)
        }
        AgentMutation::ResetBuiltin { name } => {
            validate_name(&name)?;
            if !crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("only a built-in agent can be reset"));
            }
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict(
                    "built-in override is not owned by the workspace layer",
                ));
            }
            let affected = reset_builtins_atomic_locked(root, guard, &[name.as_str()])?;
            (affected != 0, affected, Some(snapshot_sync(root, &name)?))
        }
        AgentMutation::ResetAllBuiltins => {
            let current_inventory_revision = current_inventory_revision(root)?;
            ensure_revision(&current_inventory_revision, expected_revision.as_deref())?;
            let affected =
                reset_builtins_atomic_locked(root, guard, crate::agents::BUILTIN_AGENT_NAMES)?;
            (affected != 0, affected, None)
        }
        AgentMutation::SaveGoalSupervision { name, patch } => {
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(conflict(
                    "goal settings cannot shadow an agent owned by another configuration layer",
                ));
            }
            let mut def = crate::agents::parse_agent(
                &current.markdown,
                &name,
                PathBuf::from("<daemon-agent-goal-settings>"),
            )
            .map_err(bad_config)?;
            if def.vnext.is_some() {
                return Err(bad_request(
                    "agent-scoped goal settings are unavailable for vNext agents",
                ));
            }
            if let Some(value) = patch.cold_skeptic_count {
                def.goal_supervision.cold_skeptic_count = value;
            }
            if let Some(value) = patch.cold_skeptic_model {
                def.goal_supervision.cold_skeptic_model = value;
            }
            if let Some(value) = patch.max_verification_attempts {
                def.goal_supervision.max_verification_attempts = value;
            }
            def.goal_supervision.validate().map_err(bad_config)?;
            crate::agents::validate_invariants(&def).map_err(bad_config)?;
            let markdown = def.to_markdown().map_err(bad_config)?;
            let target = project_agent_path(root, &name)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            if markdown.as_bytes() == current.markdown.as_bytes() {
                (false, 0, Some(current))
            } else {
                cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                    .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
        AgentMutation::AddMcpServer {
            name,
            server,
            server_json,
            profile,
            secret_values,
        } => {
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict(
                    "agent MCP configuration can only mutate a workspace-owned package",
                ));
            }
            let update = prepare_agent_mcp_add(
                root,
                &name,
                &server,
                &server_json,
                &profile,
                &secret_values,
                true,
            )?;
            let agent_target = project_agent_write_path(root, &name)?;
            if agent_target.file_name().and_then(|value| value.to_str()) != Some("agent.md") {
                return Err(bad_request(
                    "agent MCP configuration requires a directory-form agent package",
                ));
            }
            let package_dir = agent_target
                .parent()
                .ok_or_else(|| bad_request("agent package has no parent"))?
                .to_path_buf();
            let mcp_target = package_dir.join("mcp.json");
            let prior_agent = nofollow_read(&agent_target)?;
            let prior_mcp = nofollow_read(&mcp_target)?;
            let changed = prior_agent.as_deref() != Some(update.markdown.as_bytes())
                || prior_mcp.as_deref() != Some(update.mcp_json.as_bytes());
            if changed {
                publish_agent_package_mcp_atomic(&package_dir, &update)?;
            }
            (
                changed,
                u32::from(changed),
                Some(snapshot_sync(root, &name)?),
            )
        }
        AgentMutation::SavePackageMcp { name, mcp_json } => {
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            crate::mcp::config::McpConfig::parse(&format!("{{\"mcpServers\":{mcp_json}}}"))
                .or_else(|_| crate::mcp::config::McpConfig::parse(&mcp_json))
                .map_err(bad_config)?;
            let package_rel = format!(".cockpit/agents/{name}");
            let package_dir = crate::daemon::fs_api::resolve_authorized_canonical_path(
                root.to_string_lossy().as_ref(),
                &package_rel,
                crate::daemon::fs_api::AuthorizedCanonicalPathMode::WriteTarget,
            )
            .map_err(internal)?;
            std::fs::create_dir_all(&package_dir).map_err(internal)?;
            let agent_md = package_dir.join("agent.md");
            if !agent_md.exists() {
                cockpit_config::config::write_config_bytes_atomic(
                    &agent_md,
                    current.markdown.as_bytes(),
                )
                .map_err(internal)?;
            }
            let mcp_path = package_dir.join("mcp.json");
            let body = if mcp_json.trim_start().starts_with('{') && mcp_json.contains("mcpServers")
            {
                mcp_json
            } else {
                format!("{{\"mcpServers\":{mcp_json}}}")
            };
             cockpit_config::config::write_config_bytes_atomic(&mcp_path, body.as_bytes())
                 .map_err(internal)?;
             (true, 1, Some(snapshot_sync(root, &name)?))
        }
    };
    let generation = match durable_generation_pair {
        Some((consumed, result)) => {
            if consumed != generation_before
                || (changed && result <= consumed)
                || (!changed && result != consumed)
            {
                return Err(internal(
                    "agent editor durable generation pair is inconsistent",
                ));
            }
            crate::daemon::server::inventory::publish_committed_config_generation_at_least(result);
            result
        }
        None if changed => crate::daemon::server::inventory::publish_committed_config_generation(),
        None => generation_before,
    };
    let (result_inventory_revision, outcome) = if resets_inventory {
        match current_inventory_revision(root) {
            Ok(revision) => (
                Some(revision),
                cockpit_proto::AgentMutationOutcome::Reconciled,
            ),
            Err(_) => (
                Some(crate::daemon::authority_token::mint(
                    b"agent-reset-commit-receipt/v1",
                    &[
                        root.as_os_str().as_encoded_bytes(),
                        consumed_revision.as_deref().unwrap_or_default().as_bytes(),
                        &affected.to_le_bytes(),
                        &generation.to_le_bytes(),
                    ],
                )),
                cockpit_proto::AgentMutationOutcome::CommittedRefreshNeeded {
                    warning: "built-in overrides were committed, but the refreshed agent inventory is unavailable; reopen Agents to refresh".into(),
                },
            ),
        }
    } else if changes_mcp_binding && changed {
        (
            None,
            cockpit_proto::AgentMutationOutcome::CommittedRefreshNeeded {
                warning: "agent MCP binding committed; existing live sessions retain their current catalog until the agent is rebuilt".into(),
            },
        )
    } else {
        (None, cockpit_proto::AgentMutationOutcome::Reconciled)
    };
    let result_revision = snapshot
        .as_ref()
        .map(|snapshot| snapshot.revision.clone())
        .or_else(|| result_inventory_revision.clone())
        .unwrap_or_else(|| {
            mutation_tombstone_revision(
                &project_root,
                mutation_name.as_deref(),
                &crate::daemon::authority_token::mint(
                    b"agent-absent-projection/v1",
                    &[project_root.as_bytes()],
                ),
            )
        });
    Ok(Response::AgentMutated(AgentMutationResult {
        client_operation_id: String::new(),
        mutation_intent_hash: String::new(),
        project_root,
        requested_project_root: root.to_string_lossy().into_owned(),
        owner_scope: format!("project:{}", root.to_string_lossy()),
        agent_name: mutation_name,
        changed,
        affected,
        snapshot,
        config_generation: generation,
        consumed_config_generation: generation_before,
        result_config_generation: generation,
        inventory_revision: result_inventory_revision,
        consumed_revision,
        result_revision,
        completed_lease_id: None,
        outcome,
    }))
}

fn project_agent_path(root: &Path, name: &str) -> Result<PathBuf, ErrorPayload> {
    validate_name(name)?;
    let relative = format!(".cockpit/agents/{name}.md");
    crate::daemon::fs_api::resolve_authorized_canonical_path(
        root.to_string_lossy().as_ref(),
        &relative,
        crate::daemon::fs_api::AuthorizedCanonicalPathMode::WriteTarget,
    )
}

fn publish_agent_package_mcp_atomic(
    package_dir: &Path,
    update: &AgentMcpUpdate,
) -> Result<(), ErrorPayload> {
    let parent = package_dir
        .parent()
        .ok_or_else(|| bad_request("agent package has no parent"))?;
    let leaf = package_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| bad_request("agent package name is invalid"))?;
    let staging = parent.join(format!(".{leaf}.mcp-stage-{}", uuid::Uuid::now_v7()));
    let staged_result = (|| {
        copy_agent_package_tree(package_dir, &staging)?;
        cockpit_config::config::write_config_bytes_atomic(
            &staging.join("agent.md"),
            update.markdown.as_bytes(),
        )
        .map_err(internal)?;
        cockpit_config::config::write_config_bytes_atomic(
            &staging.join("mcp.json"),
            update.mcp_json.as_bytes(),
        )
        .map_err(internal)?;
        exchange_agent_package_dirs(package_dir, &staging)
    })();
    if staged_result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
        return staged_result;
    }
    if let Err(error) = std::fs::remove_dir_all(&staging) {
        tracing::warn!(path = %staging.display(), %error, "retaining old agent package after atomic exchange");
    }
    Ok(())
}

fn copy_agent_package_tree(source: &Path, target: &Path) -> Result<(), ErrorPayload> {
    let metadata = std::fs::symlink_metadata(source).map_err(internal)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(conflict("agent package is not a real directory"));
    }
    std::fs::create_dir(target).map_err(internal)?;
    std::fs::set_permissions(target, metadata.permissions()).map_err(internal)?;
    for entry in std::fs::read_dir(source).map_err(internal)? {
        let entry = entry.map_err(internal)?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source_path).map_err(internal)?;
        if metadata.file_type().is_symlink() {
            return Err(conflict("agent packages cannot contain symlinks"));
        }
        if metadata.is_dir() {
            copy_agent_package_tree(&source_path, &target_path)?;
        } else if metadata.is_file() {
            let bytes = nofollow_read(&source_path)?
                .ok_or_else(|| conflict("agent package file changed while staging"))?;
            cockpit_config::config::write_config_bytes_atomic(&target_path, &bytes)
                .map_err(internal)?;
        } else {
            return Err(conflict("agent package contains an unsupported file type"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exchange_agent_package_dirs(left: &Path, right: &Path) -> Result<(), ErrorPayload> {
    use std::os::unix::ffi::OsStrExt as _;
    let left = std::ffi::CString::new(left.as_os_str().as_bytes()).map_err(internal)?;
    let right = std::ffi::CString::new(right.as_os_str().as_bytes()).map_err(internal)?;
    // SAFETY: both C strings live across the syscall; RENAME_EXCHANGE swaps
    // two existing entries atomically without following either final path.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(internal(std::io::Error::last_os_error()))
    }
}

#[cfg(target_os = "macos")]
fn exchange_agent_package_dirs(left: &Path, right: &Path) -> Result<(), ErrorPayload> {
    use std::os::unix::ffi::OsStrExt as _;
    let left = std::ffi::CString::new(left.as_os_str().as_bytes()).map_err(internal)?;
    let right = std::ffi::CString::new(right.as_os_str().as_bytes()).map_err(internal)?;
    // SAFETY: both paths are valid C strings and RENAME_SWAP atomically
    // exchanges the two existing directory entries.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(internal(std::io::Error::last_os_error()))
    }
}

#[cfg(target_os = "windows")]
#[derive(serde::Serialize, serde::Deserialize)]
struct WindowsAgentPackageSwap {
    staging_leaf: String,
    backup_leaf: String,
    phase: String,
}

#[cfg(target_os = "windows")]
fn windows_agent_swap_marker(left: &Path) -> Result<PathBuf, ErrorPayload> {
    let parent = left
        .parent()
        .ok_or_else(|| bad_request("agent package has no parent"))?;
    let leaf = left
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| bad_request("agent package name is invalid"))?;
    Ok(parent.join(format!(".{leaf}.mcp-swap-state.json")))
}

#[cfg(target_os = "windows")]
fn write_windows_agent_swap(
    marker: &Path,
    state: &WindowsAgentPackageSwap,
) -> Result<(), ErrorPayload> {
    let bytes = serde_json::to_vec(state).map_err(internal)?;
    cockpit_config::config::write_config_bytes_atomic(marker, &bytes).map_err(internal)
}

#[cfg(target_os = "windows")]
fn finish_windows_agent_package_swap(
    left: &Path,
    state: &mut WindowsAgentPackageSwap,
) -> Result<(), ErrorPayload> {
    let parent = left
        .parent()
        .ok_or_else(|| bad_request("agent package has no parent"))?;
    if Path::new(&state.staging_leaf).components().count() != 1
        || Path::new(&state.backup_leaf).components().count() != 1
    {
        return Err(conflict(
            "agent package swap marker contains an invalid path",
        ));
    }
    let right = parent.join(&state.staging_leaf);
    let backup = parent.join(&state.backup_leaf);
    let marker = windows_agent_swap_marker(left)?;
    if state.phase == "prepared" {
        if left.exists() && !backup.exists() {
            std::fs::rename(left, &backup).map_err(internal)?;
        } else if left.exists() || !backup.exists() {
            return Err(conflict(
                "agent package swap prepared phase is inconsistent",
            ));
        }
        state.phase = "live_moved".into();
        write_windows_agent_swap(&marker, state)?;
    }
    if state.phase == "live_moved" {
        if !left.exists() && right.exists() && backup.exists() {
            std::fs::rename(&right, left).map_err(internal)?;
        } else if !left.exists() || right.exists() || !backup.exists() {
            return Err(conflict(
                "agent package swap live-moved phase is inconsistent",
            ));
        }
        state.phase = "staged_live".into();
        write_windows_agent_swap(&marker, state)?;
    }
    if state.phase == "staged_live" {
        if left.exists() && !right.exists() && backup.exists() {
            std::fs::rename(&backup, &right).map_err(internal)?;
        } else if !left.exists() || !right.exists() || backup.exists() {
            return Err(conflict(
                "agent package swap staged-live phase is inconsistent",
            ));
        }
        state.phase = "complete".into();
        write_windows_agent_swap(&marker, state)?;
    }
    if state.phase != "complete" {
        return Err(conflict("agent package swap marker has an invalid phase"));
    }
    std::fs::remove_file(marker).map_err(internal)
}

#[cfg(target_os = "windows")]
fn exchange_agent_package_dirs(left: &Path, right: &Path) -> Result<(), ErrorPayload> {
    let right_leaf = right
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| bad_request("agent package staging name is invalid"))?;
    let leaf = left
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| bad_request("agent package name is invalid"))?;
    let mut state = WindowsAgentPackageSwap {
        staging_leaf: right_leaf.to_owned(),
        backup_leaf: format!(".{leaf}.mcp-swap-old-{}", uuid::Uuid::now_v7()),
        phase: "prepared".into(),
    };
    write_windows_agent_swap(&windows_agent_swap_marker(left)?, &state)?;
    finish_windows_agent_package_swap(left, &mut state)
}

#[cfg(target_os = "windows")]
fn recover_windows_agent_package_swap(root: &Path, name: &str) -> Result<(), ErrorPayload> {
    validate_name(name)?;
    let left = root.join(".cockpit").join("agents").join(name);
    let marker = windows_agent_swap_marker(&left)?;
    let raw = match std::fs::read(&marker) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(internal(error)),
    };
    let mut state: WindowsAgentPackageSwap = serde_json::from_slice(&raw).map_err(internal)?;
    finish_windows_agent_package_swap(&left, &mut state)?;
    let old_package = left
        .parent()
        .expect("agent package has parent")
        .join(&state.staging_leaf);
    std::fs::remove_dir_all(old_package).map_err(internal)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn exchange_agent_package_dirs(_left: &Path, _right: &Path) -> Result<(), ErrorPayload> {
    Err(bad_request(
        "atomic agent-package MCP publication is unavailable on this platform",
    ))
}

/// Write target for a workspace mutation: `agents/<name>/agent.md` when a
/// package already exists, otherwise the single-file `agents/<name>.md`.
fn project_agent_write_path(root: &Path, name: &str) -> Result<PathBuf, ErrorPayload> {
    validate_name(name)?;
    let package_dir_rel = format!(".cockpit/agents/{name}");
    if let Ok(dir) = crate::daemon::fs_api::resolve_authorized_canonical_path(
        root.to_string_lossy().as_ref(),
        &package_dir_rel,
        crate::daemon::fs_api::AuthorizedCanonicalPathMode::WriteTarget,
    ) && dir.is_dir()
    {
        return crate::daemon::fs_api::resolve_authorized_canonical_path(
            root.to_string_lossy().as_ref(),
            &format!(".cockpit/agents/{name}/agent.md"),
            crate::daemon::fs_api::AuthorizedCanonicalPathMode::WriteTarget,
        );
    }
    project_agent_path(root, name)
}

fn validate_name(name: &str) -> Result<(), ErrorPayload> {
    if name.is_empty()
        || name.len() > cockpit_proto::MAX_AGENT_NAME_BYTES
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(bad_request("agent name is invalid"));
    }
    Ok(())
}

fn nofollow_read(path: &Path) -> Result<Option<Vec<u8>>, ErrorPayload> {
    cockpit_config::config::read_config_file_nofollow(path).map_err(internal)
}

fn classify_source_layer(root: &Path, source: &Path, target: &Path) -> AgentSourceLayer {
    if source == target {
        return AgentSourceLayer::Workspace;
    }
    // A workspace package lives at `.cockpit/agents/<name>/` while the
    // historical write target is `.cockpit/agents/<name>.md`. Treat the
    // package directory (or its `agent.md`) as workspace-owned.
    if source.is_dir() {
        if source.join("agent.md") == target || source.parent() == target.parent() {
            return AgentSourceLayer::Workspace;
        }
    } else if source.file_name().and_then(|n| n.to_str()) == Some("agent.md")
        && source
            .parent()
            .is_some_and(|parent| parent.parent() == target.parent())
    {
        return AgentSourceLayer::Workspace;
    }
    // Flat definitions are owned by their exact parent directory. Prefix
    // matching misclassified nested configured directories according to the
    // first broader layer rather than the effective, most-specific owner.
    let Some(owner) = source.parent() else {
        return AgentSourceLayer::OtherConfigLayer;
    };
    let ordinary: std::collections::HashSet<PathBuf> =
        crate::config::dirs::discover_config_dirs(root)
            .into_iter()
            .map(|dir| dir.path.join("agents"))
            .collect();
    if ordinary.contains(owner) {
        AgentSourceLayer::OtherConfigLayer
    } else if crate::agents::agent_search_dirs(root)
        .into_iter()
        .any(|dir| dir == owner)
    {
        AgentSourceLayer::ConfiguredDirectory
    } else {
        AgentSourceLayer::OtherConfigLayer
    }
}

fn ensure_workspace_source_or_embedded(snapshot: &AgentEditSnapshot) -> Result<(), ErrorPayload> {
    if matches!(
        snapshot.source_layer,
        AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
    ) {
        Ok(())
    } else {
        Err(conflict(
            "eject refused: another configuration layer already owns this override",
        ))
    }
}

fn embedded_source_identity(root: &Path, name: &str, content: &[u8]) -> String {
    crate::daemon::authority_token::mint(
        b"agent-source/embedded/v1",
        &[
            root.as_os_str().as_encoded_bytes(),
            name.as_bytes(),
            content,
        ],
    )
}

fn opaque_source_identity(
    root: &Path,
    source: &Path,
    layer: AgentSourceLayer,
    content: &[u8],
) -> Result<String, ErrorPayload> {
    let metadata = std::fs::symlink_metadata(source).map_err(internal)?;
    if metadata.file_type().is_symlink() {
        return Err(conflict(
            "agent source became a symlink while minting its identity",
        ));
    }
    let layer = [layer as u8];
    let length = metadata.len().to_le_bytes();
    let mut platform_identity = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        platform_identity.extend_from_slice(&metadata.dev().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.ino().to_le_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        platform_identity.extend_from_slice(&metadata.file_attributes().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.creation_time().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.last_write_time().to_le_bytes());
    }
    Ok(crate::daemon::authority_token::mint(
        b"agent-source/file/v1",
        &[
            &layer,
            root.as_os_str().as_encoded_bytes(),
            source.as_os_str().as_encoded_bytes(),
            content,
            &length,
            &platform_identity,
        ],
    ))
}

fn current_inventory_revision(root: &Path) -> Result<String, ErrorPayload> {
    Ok(inventory_revision(&inventory_entries(root)?))
}

fn definition_revision(
    name: &str,
    source_layer: AgentSourceLayer,
    source_identity: &str,
    source_content_hash: &str,
    target_exists: bool,
) -> String {
    let layer = [source_layer as u8];
    let exists = [u8::from(target_exists)];
    crate::daemon::authority_token::mint(
        b"agent-definition-revision/v1",
        &[
            name.as_bytes(),
            &layer,
            source_identity.as_bytes(),
            source_content_hash.as_bytes(),
            &exists,
        ],
    )
}

fn inventory_revision(entries: &[AgentInventoryEntry]) -> String {
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let mut canonical = Vec::new();
    for entry in ordered {
        for value in [&entry.name, &entry.source_identity, &entry.revision] {
            canonical.extend_from_slice(&(value.len() as u64).to_le_bytes());
            canonical.extend_from_slice(value.as_bytes());
        }
        canonical.extend_from_slice(&[
            entry.kind as u8,
            u8::from(entry.overridden),
            u8::from(entry.editable),
        ]);
    }
    crate::daemon::authority_token::mint(b"agent-inventory-revision/v1", &[&canonical])
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ResetAllJournal {
    operation_id: String,
    #[serde(default = "prepared_reset_phase")]
    phase: ResetAllPhase,
    #[serde(default = "reset_builtins_removal_kind")]
    kind: AgentRemovalKind,
    /// Validated names admitted by `kind`. Paths and staging names are always
    /// derived by the daemon after parsing the journal.
    entries: Vec<ResetAllEntry>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ResetAllEntry {
    name: String,
    package: bool,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResetAllPhase {
    Prepared,
    Committed,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AgentRemovalKind {
    ResetBuiltins,
    DeleteCustom,
}

fn reset_builtins_removal_kind() -> AgentRemovalKind {
    AgentRemovalKind::ResetBuiltins
}

fn prepared_reset_phase() -> ResetAllPhase {
    ResetAllPhase::Prepared
}

fn reset_journal_path(root: &Path) -> PathBuf {
    root.join(".cockpit/agent-reset-all.journal.json")
}

fn validated_reset_journal(
    root: &Path,
    raw: &[u8],
) -> Result<(ResetAllJournal, PathBuf), ErrorPayload> {
    let journal: ResetAllJournal = serde_json::from_slice(raw).map_err(bad_config)?;
    let operation_id = Uuid::parse_str(&journal.operation_id)
        .map_err(|_| bad_request("agent reset journal has an invalid operation ID"))?;
    if operation_id.to_string() != journal.operation_id {
        return Err(bad_request(
            "agent reset journal operation ID is not canonical",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for entry in &journal.entries {
        validate_name(&entry.name)?;
        let allowed_name = match journal.kind {
            AgentRemovalKind::ResetBuiltins => crate::agents::is_builtin_agent(&entry.name),
            AgentRemovalKind::DeleteCustom => !crate::agents::is_builtin_agent(&entry.name),
        };
        if !allowed_name || !seen.insert(entry.name.clone()) {
            return Err(bad_request("agent reset journal contains an invalid entry"));
        }
    }
    if journal.kind == AgentRemovalKind::DeleteCustom && journal.entries.len() != 1 {
        return Err(bad_request(
            "custom agent deletion journal must contain exactly one entry",
        ));
    }
    let trash_root = root.join(".cockpit/.agent-reset-trash");
    if std::fs::symlink_metadata(&trash_root)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(bad_request("agent reset trash root is a symlink"));
    }
    let trash = trash_root.join(operation_id.to_string());
    // Reject substituted staging directories. We never recurse through this
    // path; each expected leaf is derived from a validated agent name.
    if std::fs::symlink_metadata(&trash).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(bad_request("agent reset staging directory is a symlink"));
    }
    Ok((journal, trash))
}

fn staged_agent_path(trash: &Path, entry: &ResetAllEntry) -> Result<PathBuf, ErrorPayload> {
    validate_name(&entry.name)?;
    Ok(if entry.package {
        trash.join(&entry.name)
    } else {
        trash.join(format!("{}.md", entry.name))
    })
}

fn owned_package_dir(flat: &Path, name: &str) -> Result<Option<PathBuf>, ErrorPayload> {
    let package = flat.with_file_name(name);
    let package_metadata = match std::fs::symlink_metadata(&package) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(internal(error)),
    };
    if package_metadata.file_type().is_symlink() || !package_metadata.is_dir() {
        return Err(conflict(
            "workspace agent package is not an owned directory",
        ));
    }
    let definition = std::fs::symlink_metadata(package.join("agent.md")).map_err(internal)?;
    if definition.file_type().is_symlink() || !definition.is_file() {
        return Err(conflict("workspace agent package has no owned agent.md"));
    }
    Ok(Some(package))
}

fn sync_dir(path: &Path) -> Result<(), ErrorPayload> {
    cockpit_config::config::sync_directory_nofollow(path).map_err(internal)
}

/// Recover an interrupted reset conservatively by restoring every staged
/// override. A reset is externally committed only after every rename lands
/// and the journal is removed, so boot/request recovery never exposes a
/// silently partial reset as success.
fn recover_reset_all_locked(
    root: &Path,
    guard: &cockpit_config::config::HeldConfigMutationLock,
) -> Result<(), ErrorPayload> {
    let journal_path = reset_journal_path(root);
    let Some(raw) = nofollow_read(&journal_path)? else {
        return Ok(());
    };
    let (journal, trash) = validated_reset_journal(root, &raw)?;
    let agents_dir = root.join(".cockpit/agents");
    match journal.phase {
        ResetAllPhase::Prepared => {
            for entry in journal.entries.iter().rev() {
                let flat = project_agent_path(root, &entry.name)?;
                let target = if entry.package {
                    flat.with_file_name(&entry.name)
                } else {
                    flat
                };
                let staged = staged_agent_path(&trash, entry)?;
                let staged_exists = std::fs::symlink_metadata(&staged).is_ok();
                let target_exists = std::fs::symlink_metadata(&target).is_ok();
                match (staged_exists, target_exists) {
                    (true, false) => {
                        rename_reset_entry_noreplace(guard, &staged, &target, entry.package)?
                    }
                    // This entry was not staged yet, or an earlier recovery
                    // pass already restored it.
                    (false, true) => {}
                    (true, true) => {
                        if !entry.package
                            && cockpit_config::config::same_config_file_identity_nofollow(
                                &staged, &target,
                            )
                            .map_err(internal)?
                        {
                            // Portable link/unlink no-replace can durably
                            // publish the second name before unlinking the
                            // first. Prepared recovery treats identical names
                            // as a recoverable rollback state and retains the
                            // authoritative target.
                            cockpit_config::config::remove_config_file_atomic(&staged)
                                .map_err(internal)?;
                        } else {
                            return Err(conflict(
                                "agent reset rollback found different staged and authoritative files",
                            ));
                        }
                    }
                    (false, false) => {
                        return Err(conflict(
                            "agent reset rollback found neither staged nor authoritative file",
                        ));
                    }
                }
            }
            if agents_dir.is_dir() {
                sync_dir(&agents_dir)?;
            }
            if trash.is_dir() {
                sync_dir(&trash)?;
            }
        }
        ResetAllPhase::Committed => {
            for entry in &journal.entries {
                let staged = staged_agent_path(&trash, entry)?;
                let flat = project_agent_path(root, &entry.name)?;
                let target = if entry.package {
                    flat.with_file_name(&entry.name)
                } else {
                    flat
                };
                let staged_exists = std::fs::symlink_metadata(&staged).is_ok();
                let target_exists = std::fs::symlink_metadata(&target).is_ok();
                match (staged_exists, target_exists) {
                    (true, false) if entry.package => {
                        std::fs::remove_dir_all(&staged).map_err(internal)?
                    }
                    (true, false) => cockpit_config::config::remove_config_file_atomic(&staged)
                        .map_err(internal)?,
                    // A previous committed recovery already deleted it.
                    (false, false) => {}
                    // Once committed, an authoritative target is unexpected;
                    // never bless or delete it because it may be newer data.
                    (_, true) => {
                        return Err(conflict(
                            "committed agent reset found an unexpected authoritative file",
                        ));
                    }
                }
            }
            if trash.is_dir() {
                sync_dir(&trash)?;
            }
        }
    }
    cockpit_config::config::remove_config_file_atomic(&journal_path).map_err(internal)?;
    sync_dir(journal_path.parent().expect("journal has parent"))?;
    if trash.is_dir() {
        std::fs::remove_dir(&trash).map_err(internal)?;
        sync_dir(trash.parent().expect("trash operation has parent"))?;
    }
    Ok(())
}

pub async fn recover_known_workspace_resets(
    ctx: &DaemonContext,
    publication: crate::daemon::config_publication_recovery::PreSocketConfigPublication,
) -> Result<(), ErrorPayload> {
    let sessions = ctx
        .db
        .list_sessions(false, 100_000)
        .await
        .map_err(internal)?;
    let mut roots = std::collections::BTreeSet::new();
    roots.extend(sessions.into_iter().map(|session| session.project_root));
    // Reset-all recovery is a dependency of every agent mutation journal. A
    // workspace need not have a retained session, so derive the boot recovery
    // inventory from the authority journals themselves as well.
    let journal_roots: Vec<String> = ctx
        .db
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT project_root FROM agent_mutation_journals ORDER BY project_root",
            )?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
        .await
        .map_err(internal)?;
    roots.extend(journal_roots);
    let mut trusted_roots = Vec::new();
    for root in roots {
        let historical = PathBuf::from(&root);
        match std::fs::symlink_metadata(reset_journal_path(&historical)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(internal(error)),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(bad_request("historical agent reset journal is a symlink"));
            }
            Ok(_) => {}
        }
        let root = crate::daemon::fs_api::canonical_project_root(&root)?;
        let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
            .await
            .map_err(internal)?;
        if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
            return Err(ErrorPayload {
                code: ErrorCode::WorkspaceTrust,
                message: format!(
                    "refusing agent reset recovery for untrusted historical root {}",
                    root.display()
                ),
            });
        }
        trusted_roots.push(root);
    }
    for root in trusted_roots {
        let lock_target = root.join(".cockpit/config.json");
        publication
            .with_target(&lock_target, move |guard| {
                recover_reset_all_locked(&root, guard)
                    .map_err(|error| anyhow::anyhow!(error.message))
            })
            .await
            .map_err(|error| ErrorPayload {
                code: ErrorCode::Shutdown,
                message: format!(
                    "bounded agent-reset recovery could not acquire publication authority: {error:#}"
                ),
            })?;
    }
    Ok(())
}

fn reset_builtins_atomic_locked(
    root: &Path,
    guard: &cockpit_config::config::HeldConfigMutationLock,
    names: &[&str],
) -> Result<u32, ErrorPayload> {
    recover_reset_all_locked(root, guard)?;
    let mut entries = Vec::new();
    for name in names {
        let flat = project_agent_path(root, name)?;
        if let Some(package) = owned_package_dir(&flat, name)? {
            let _ = package;
            entries.push(ResetAllEntry {
                name: (*name).to_string(),
                package: true,
            });
        } else if nofollow_read(&flat)?.is_some() {
            entries.push(ResetAllEntry {
                name: (*name).to_string(),
                package: false,
            });
        }
    }
    remove_agent_entries_atomic_locked(root, guard, entries, AgentRemovalKind::ResetBuiltins)
}

fn delete_custom_atomic_locked(
    root: &Path,
    guard: &cockpit_config::config::HeldConfigMutationLock,
    name: &str,
) -> Result<u32, ErrorPayload> {
    recover_reset_all_locked(root, guard)?;
    let flat = project_agent_path(root, name)?;
    let entry = if owned_package_dir(&flat, name)?.is_some() {
        ResetAllEntry {
            name: name.to_string(),
            package: true,
        }
    } else if nofollow_read(&flat)?.is_some() {
        ResetAllEntry {
            name: name.to_string(),
            package: false,
        }
    } else {
        return Err(bad_request(
            "custom agent is not owned by this workspace layer",
        ));
    };
    remove_agent_entries_atomic_locked(root, guard, vec![entry], AgentRemovalKind::DeleteCustom)
}

fn remove_agent_entries_atomic_locked(
    root: &Path,
    guard: &cockpit_config::config::HeldConfigMutationLock,
    entries: Vec<ResetAllEntry>,
    kind: AgentRemovalKind,
) -> Result<u32, ErrorPayload> {
    if entries.is_empty() {
        return Ok(0);
    }
    let operation_id = Uuid::new_v4();
    let trash = root
        .join(".cockpit/.agent-reset-trash")
        .join(operation_id.to_string());
    let trash_root = trash.parent().expect("trash has parent");
    cockpit_host::private_fs::ensure_private_dir(trash_root).map_err(internal)?;
    #[cfg(unix)]
    let _trash_root_handle =
        cockpit_host::private_fs::open_private_dir_handle(trash_root).map_err(internal)?;
    cockpit_host::private_fs::ensure_private_dir(&trash).map_err(internal)?;
    #[cfg(unix)]
    let _trash_handle =
        cockpit_host::private_fs::open_private_dir_handle(&trash).map_err(internal)?;
    // The prepared journal may refer to this staging directory immediately
    // after publication, so persist both the directory itself and its parent
    // first. Recovery must never observe a durable journal naming a directory
    // that existed only in volatile metadata.
    sync_dir(&trash)?;
    sync_dir(trash_root)?;
    let journal = ResetAllJournal {
        operation_id: operation_id.to_string(),
        phase: ResetAllPhase::Prepared,
        kind,
        entries,
    };
    let encoded = serde_json::to_vec_pretty(&journal).map_err(internal)?;
    cockpit_config::config::write_config_bytes_atomic(&reset_journal_path(root), &encoded)
        .map_err(internal)?;

    let agents_dir = root.join(".cockpit/agents");
    for entry in &journal.entries {
        let flat = project_agent_path(root, &entry.name)?;
        let source = if entry.package {
            flat.with_file_name(&entry.name)
        } else {
            flat
        };
        let staged = staged_agent_path(&trash, entry)?;
        if let Err(error) = rename_reset_entry_noreplace(guard, &source, &staged, entry.package) {
            // The durable journal makes rollback retryable if this immediate
            // recovery itself encounters an I/O failure.
            let _ = recover_reset_all_locked(root, guard);
            return Err(error);
        }
    }
    sync_dir(&agents_dir)?;
    sync_dir(&trash)?;
    // The committed marker is the linearization point. Recovery before it
    // restores staged files; recovery after it finishes deletion.
    let committed = ResetAllJournal {
        phase: ResetAllPhase::Committed,
        ..journal
    };
    let encoded = serde_json::to_vec_pretty(&committed).map_err(internal)?;
    cockpit_config::config::write_config_bytes_atomic(&reset_journal_path(root), &encoded)
        .map_err(internal)?;
    recover_reset_all_locked(root, guard)?;
    Ok(committed.entries.len() as u32)
}

fn rename_reset_entry_noreplace(
    guard: &cockpit_config::config::HeldConfigMutationLock,
    source: &Path,
    destination: &Path,
    package: bool,
) -> Result<(), ErrorPayload> {
    if !package {
        return rename_config_noreplace(guard, source, destination);
    }
    rename_directory_noreplace(source, destination)
}

fn rename_directory_noreplace(source: &Path, destination: &Path) -> Result<(), ErrorPayload> {
    cockpit_host::private_fs::rename_directory_noreplace(source, destination).map_err(|error| {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
        {
            conflict(format!(
                "agent reset destination already exists: {}",
                destination.display()
            ))
        } else {
            internal(error)
        }
    })
}

fn ensure_revision(current: &str, expected: Option<&str>) -> Result<(), ErrorPayload> {
    match expected {
        Some(expected) if expected == current => Ok(()),
        Some(_) => Err(conflict("agent changed since the snapshot was read")),
        None => Err(conflict("agent mutation requires an expected revision")),
    }
}

fn rename_config_noreplace(
    guard: &cockpit_config::config::HeldConfigMutationLock,
    source: &Path,
    destination: &Path,
) -> Result<(), ErrorPayload> {
    cockpit_config::config::rename_config_file_nofollow(guard, source, destination).map_err(
        |error| {
            let destination_exists = error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
            });
            if destination_exists {
                conflict(format!(
                    "agent reset destination already exists: {}",
                    destination.display()
                ))
            } else {
                internal(error)
            }
        },
    )
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

pub(crate) fn bad_config(error: impl std::fmt::Display) -> ErrorPayload {
    bad_request(format!("invalid agent definition: {error}"))
}

pub(crate) fn conflict(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Conflict,
        message: message.into(),
    }
}

fn internal(error: impl std::fmt::Display) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("agent management failed: {error}"),
    }
}

fn join_error(error: tokio::task::JoinError) -> ErrorPayload {
    internal(format!("agent management worker failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_package_delete_stages_and_removes_the_whole_directory() {
        let root = tempfile::TempDir::new().expect("workspace");
        let package = root.path().join(".cockpit/agents/reviewer");
        std::fs::create_dir_all(package.join("subagents")).expect("package directories");
        std::fs::write(package.join("agent.md"), b"root").expect("root definition");
        std::fs::write(package.join("subagents/helper.md"), b"private").expect("private child");
        std::fs::write(package.join("mcp.json"), b"{}").expect("package MCP");
        let guard = cockpit_config::config::hold_config_mutation_lock(
            &root.path().join(".cockpit/config.json"),
        )
        .expect("mutation lock");

        assert_eq!(
            delete_custom_atomic_locked(root.path(), &guard, "reviewer").expect("delete package"),
            1
        );
        assert!(
            !package.exists(),
            "acknowledged absence covers the whole package"
        );
        assert!(!reset_journal_path(root.path()).exists());
    }

    #[test]
    fn package_missing_agent_md_is_still_projection_present() {
        let root = tempfile::TempDir::new().expect("workspace");
        let package = root.path().join(".cockpit/agents/reviewer");
        std::fs::create_dir_all(package.join("subagents")).expect("package directories");
        std::fs::write(package.join("subagents/helper.md"), b"orphan").expect("orphan child");

        assert!(
            current_definition_bytes(root.path(), "reviewer")
                .expect("projection")
                .is_some(),
            "losing agent.md alone must not satisfy whole-package deletion"
        );
    }
}
